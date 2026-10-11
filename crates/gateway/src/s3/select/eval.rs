//! Binding a parsed statement to an input's columns, and evaluating it on
//! records.
//!
//! Binding resolves each name once, when the columns are known (a CSV
//! object's header, a Parquet file's schema): a column becomes its index,
//! so a record's field is found without a lookup. JSON has no columns to
//! know, so its names stay paths into each record.
//!
//! Names, in order: the FROM alias (`s.name`); a column (`_N` by position
//! in CSV, a header or Parquet column by name, case-insensitive unless
//! quoted); in CSV and Parquet, a select-list alias, standing for that
//! item's expression (as RGW does: `SELECT a+b AS c ... WHERE c > 1`); a
//! quoted name that is none of these is a string (RGW writes strings in
//! double quotes). In JSON `_1` is the record when it has no field `_1`.

use super::datetime::{self, Ts};
use super::error::{SelectError, SelectResult};
use super::sql::{Agg, BinOp, Expr, Func, IsWhat, Projection, Query, Step, TrimWhere};
use super::value::{CastType, Value, compare, equals};
use std::cmp::Ordering;

/// The columns a statement is bound to.
#[derive(Debug, Clone, Copy)]
pub enum Schema<'a> {
    /// CSV: the header's names when FileHeaderInfo is USE.
    Csv(Option<&'a [String]>),
    Json,
    /// Parquet: the top-level columns.
    Parquet(&'a [String]),
}

/// A record as the evaluator sees it.
#[derive(Debug, Clone, Copy)]
pub enum Rec<'a> {
    /// CSV fields.
    Fields(&'a [String]),
    /// A JSON value, or a Parquet row (a struct of its columns).
    Value(&'a Value),
}

/// A bound statement, ready to run.
#[derive(Debug)]
pub struct Plan {
    /// The select list, with each item's output name (JSON output); `None`
    /// for `*`.
    pub items: Option<Vec<(Expr, String)>>,
    pub condition: Option<Expr>,
    /// The aggregates' arguments (`None`: `COUNT(*)`), by slot.
    pub aggs: Vec<(Agg, Option<Expr>)>,
    pub limit: Option<u64>,
    /// `UTCNOW()`: one instant for the whole statement.
    pub now: Ts,
}

impl Plan {
    /// Whether the statement aggregates (one output row).
    pub fn aggregates(&self) -> bool {
        !self.aggs.is_empty()
    }
}

fn err(code: &'static str, message: impl Into<String>) -> SelectError {
    SelectError::new(code, message)
}

/// A positional CSV name, `_N` (1-based): `Some(N - 1)`.
fn positional(name: &str) -> Option<SelectResult<usize>> {
    let digits = name.strip_prefix('_')?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(match digits.parse::<usize>() {
        Ok(n) if n >= 1 => Ok(n - 1),
        _ => Err(err(
            "InvalidColumnIndex",
            format!("{name} is not a column: positions start at _1"),
        )),
    })
}

struct Binder<'a> {
    schema: Schema<'a>,
    from_alias: Option<&'a str>,
    items: &'a [super::sql::Item],
    /// Aliases being expanded, to catch one defined through itself.
    expanding: Vec<usize>,
    aggs: Vec<(Agg, Option<Expr>)>,
}

impl Binder<'_> {
    fn column(&self, step: &Step) -> Option<SelectResult<usize>> {
        let Step::Key { name, exact } = step else {
            return None;
        };
        let by_name = |names: &[String]| {
            names.iter().position(|n| n == name).or_else(|| {
                if *exact {
                    None
                } else {
                    names.iter().position(|n| n.eq_ignore_ascii_case(name))
                }
            })
        };
        match self.schema {
            Schema::Csv(header) => {
                if let Some(i) = header.and_then(by_name) {
                    return Some(Ok(i));
                }
                // `"_3"` is a string, not the third column: RGW writes
                // strings in double quotes (`_1 LIKE "_3"`).
                if *exact { None } else { positional(name) }
            }
            Schema::Parquet(names) => by_name(names).map(Ok),
            Schema::Json => None,
        }
    }

    fn alias(&self, step: &Step) -> Option<usize> {
        let Step::Key { name, exact: false } = step else {
            return None;
        };
        if matches!(self.schema, Schema::Json) {
            return None;
        }
        self.items.iter().position(|it| {
            it.alias
                .as_deref()
                .is_some_and(|a| a.eq_ignore_ascii_case(name))
        })
    }

    fn name(&mut self, steps: &[Step], in_agg: bool) -> SelectResult<Expr> {
        let mut steps = steps;
        if let (Some(alias), Some(Step::Key { name, .. })) = (self.from_alias, steps.first())
            && name.eq_ignore_ascii_case(alias)
        {
            if steps.len() == 1 {
                return Ok(Expr::Record);
            }
            steps = &steps[1..];
        }
        let head = &steps[0];
        let rest = steps[1..].to_vec();
        if let Some(col) = self.column(head) {
            return Ok(Expr::Field(col?, rest));
        }
        if matches!(self.schema, Schema::Json) {
            return Ok(Expr::Path(steps.to_vec()));
        }
        if rest.is_empty()
            && let Some(i) = self.alias(head)
        {
            if self.expanding.contains(&i) {
                return Err(err(
                    "ParseUnsupportedAlias",
                    format!(
                        "alias {} is defined through itself: number of calls exceed maximum size, probably a cyclic reference to alias",
                        self.items[i].alias.as_deref().unwrap_or_default()
                    ),
                ));
            }
            self.expanding.push(i);
            let bound = self.expr(&self.items[i].expr, in_agg);
            self.expanding.pop();
            return bound;
        }
        match head {
            Step::Key { name, exact: true } if rest.is_empty() => {
                Ok(Expr::Lit(Value::Str(name.clone())))
            }
            Step::Key { name, .. } => Err(err(
                "MissingHeaders",
                format!("Some headers in the query are missing from the file: {name}"),
            )),
            _ => Err(err("InvalidKeyPath", "a path must start with a name")),
        }
    }

    fn boxed(&mut self, e: &Expr, in_agg: bool) -> SelectResult<Box<Expr>> {
        Ok(Box::new(self.expr(e, in_agg)?))
    }

    fn list(&mut self, es: &[Expr], in_agg: bool) -> SelectResult<Vec<Expr>> {
        es.iter().map(|e| self.expr(e, in_agg)).collect()
    }

    /// Bind `e`. `in_agg`: inside an aggregate's argument (or WHERE, where
    /// aggregates aren't allowed either).
    fn expr(&mut self, e: &Expr, in_agg: bool) -> SelectResult<Expr> {
        Ok(match e {
            Expr::Name(steps) => self.name(steps, in_agg)?,
            Expr::Lit(_) | Expr::Field(..) | Expr::Path(_) | Expr::Record => e.clone(),
            Expr::Neg(a) => Expr::Neg(self.boxed(a, in_agg)?),
            Expr::Not(a) => Expr::Not(self.boxed(a, in_agg)?),
            Expr::Bin(op, a, b) => Expr::Bin(*op, self.boxed(a, in_agg)?, self.boxed(b, in_agg)?),
            Expr::And(a, b) => Expr::And(self.boxed(a, in_agg)?, self.boxed(b, in_agg)?),
            Expr::Or(a, b) => Expr::Or(self.boxed(a, in_agg)?, self.boxed(b, in_agg)?),
            Expr::Like {
                expr,
                pattern,
                escape,
                negated,
            } => Expr::Like {
                expr: self.boxed(expr, in_agg)?,
                pattern: self.boxed(pattern, in_agg)?,
                escape: match escape {
                    Some(x) => Some(self.boxed(x, in_agg)?),
                    None => None,
                },
                negated: *negated,
            },
            Expr::Between {
                expr,
                low,
                high,
                negated,
            } => Expr::Between {
                expr: self.boxed(expr, in_agg)?,
                low: self.boxed(low, in_agg)?,
                high: self.boxed(high, in_agg)?,
                negated: *negated,
            },
            Expr::In {
                expr,
                list,
                negated,
            } => Expr::In {
                expr: self.boxed(expr, in_agg)?,
                list: self.list(list, in_agg)?,
                negated: *negated,
            },
            Expr::Is {
                expr,
                what,
                negated,
            } => Expr::Is {
                expr: self.boxed(expr, in_agg)?,
                what: *what,
                negated: *negated,
            },
            Expr::Case {
                operand,
                whens,
                otherwise,
            } => Expr::Case {
                operand: match operand {
                    Some(x) => Some(self.boxed(x, in_agg)?),
                    None => None,
                },
                whens: whens
                    .iter()
                    .map(|(w, t)| Ok((self.expr(w, in_agg)?, self.expr(t, in_agg)?)))
                    .collect::<SelectResult<_>>()?,
                otherwise: match otherwise {
                    Some(x) => Some(self.boxed(x, in_agg)?),
                    None => None,
                },
            },
            Expr::Cast(a, ty) => Expr::Cast(self.boxed(a, in_agg)?, *ty),
            Expr::Call(f, args) => Expr::Call(*f, self.list(args, in_agg)?),
            Expr::Agg(agg, arg, _) => {
                if in_agg {
                    return Err(err(
                        "ParseUnsupportedSyntax",
                        "an aggregate is not allowed in WHERE or inside another aggregate",
                    ));
                }
                let arg = match arg {
                    Some(a) => Some(self.expr(a, true)?),
                    None => None,
                };
                self.aggs.push((*agg, arg));
                Expr::Agg(*agg, None, self.aggs.len() - 1)
            }
        })
    }
}

/// Whether `e` reads the record outside an aggregate.
fn reads_record(e: &Expr) -> bool {
    let mut found = false;
    visit(e, &mut |x| {
        if matches!(x, Expr::Field(..) | Expr::Path(_) | Expr::Record) {
            found = true;
        }
        !matches!(x, Expr::Agg(..))
    });
    found
}

/// Call `f` on `e` and, while it returns true, on its children.
pub fn visit(e: &Expr, f: &mut impl FnMut(&Expr) -> bool) {
    if !f(e) {
        return;
    }
    match e {
        Expr::Neg(a) | Expr::Not(a) | Expr::Cast(a, _) => visit(a, f),
        Expr::Bin(_, a, b) | Expr::And(a, b) | Expr::Or(a, b) => {
            visit(a, f);
            visit(b, f);
        }
        Expr::Like {
            expr,
            pattern,
            escape,
            ..
        } => {
            visit(expr, f);
            visit(pattern, f);
            if let Some(x) = escape {
                visit(x, f);
            }
        }
        Expr::Between {
            expr, low, high, ..
        } => {
            visit(expr, f);
            visit(low, f);
            visit(high, f);
        }
        Expr::In { expr, list, .. } => {
            visit(expr, f);
            list.iter().for_each(|x| visit(x, f));
        }
        Expr::Is { expr, .. } => visit(expr, f),
        Expr::Case {
            operand,
            whens,
            otherwise,
        } => {
            if let Some(x) = operand {
                visit(x, f);
            }
            for (w, t) in whens {
                visit(w, f);
                visit(t, f);
            }
            if let Some(x) = otherwise {
                visit(x, f);
            }
        }
        Expr::Call(_, args) => args.iter().for_each(|x| visit(x, f)),
        Expr::Agg(_, Some(a), _) => visit(a, f),
        Expr::Lit(_)
        | Expr::Name(_)
        | Expr::Agg(_, None, _)
        | Expr::Field(..)
        | Expr::Path(_)
        | Expr::Record => {}
    }
}

/// Change every `Field(i, ..)` to `Field(map(i), ..)`.
pub fn remap_fields(e: &mut Expr, map: &impl Fn(usize) -> usize) {
    match e {
        Expr::Field(i, _) => *i = map(*i),
        Expr::Neg(a) | Expr::Not(a) | Expr::Cast(a, _) => remap_fields(a, map),
        Expr::Bin(_, a, b) | Expr::And(a, b) | Expr::Or(a, b) => {
            remap_fields(a, map);
            remap_fields(b, map);
        }
        Expr::Like {
            expr,
            pattern,
            escape,
            ..
        } => {
            remap_fields(expr, map);
            remap_fields(pattern, map);
            if let Some(x) = escape {
                remap_fields(x, map);
            }
        }
        Expr::Between {
            expr, low, high, ..
        } => {
            remap_fields(expr, map);
            remap_fields(low, map);
            remap_fields(high, map);
        }
        Expr::In { expr, list, .. } => {
            remap_fields(expr, map);
            list.iter_mut().for_each(|x| remap_fields(x, map));
        }
        Expr::Is { expr, .. } => remap_fields(expr, map),
        Expr::Case {
            operand,
            whens,
            otherwise,
        } => {
            if let Some(x) = operand {
                remap_fields(x, map);
            }
            for (w, t) in whens {
                remap_fields(w, map);
                remap_fields(t, map);
            }
            if let Some(x) = otherwise {
                remap_fields(x, map);
            }
        }
        Expr::Call(_, args) => args.iter_mut().for_each(|x| remap_fields(x, map)),
        Expr::Agg(_, Some(a), _) => remap_fields(a, map),
        Expr::Lit(_) | Expr::Name(_) | Expr::Agg(_, None, _) | Expr::Path(_) | Expr::Record => {}
    }
}

/// The output name of a select item without an alias: a column's or path's
/// last name, else `_N` by position.
fn output_name(e: &Expr, n: usize) -> String {
    if let Expr::Name(steps) = e
        && let Some(Step::Key { name, .. }) = steps.last()
    {
        return name.clone();
    }
    format!("_{n}")
}

/// Bind `query` to `schema`.
pub fn bind(query: &Query, schema: Schema<'_>) -> SelectResult<Plan> {
    let items = match &query.projection {
        Projection::Star => None,
        Projection::Items(items) => Some(items.as_slice()),
    };
    let mut b = Binder {
        schema,
        from_alias: query.from_alias.as_deref(),
        items: items.unwrap_or_default(),
        expanding: Vec::new(),
        aggs: Vec::new(),
    };
    let bound_items = match items {
        None => None,
        Some(items) => {
            let mut out = Vec::with_capacity(items.len());
            for (n, item) in items.iter().enumerate() {
                let e = b.expr(&item.expr, false)?;
                let name = item
                    .alias
                    .clone()
                    .unwrap_or_else(|| output_name(&item.expr, n + 1));
                out.push((e, name));
            }
            Some(out)
        }
    };
    let condition = match &query.condition {
        Some(c) => Some(b.expr(c, true).map_err(|e| {
            if e.code == "ParseUnsupportedSyntax" {
                err(
                    "ParseUnsupportedSyntax",
                    "an aggregate is not allowed in WHERE",
                )
            } else {
                e
            }
        })?),
        None => None,
    };
    if !b.aggs.is_empty()
        && let Some(items) = &bound_items
        && items.iter().any(|(e, _)| reads_record(e))
    {
        return Err(err(
            "ParseUnsupportedSyntax",
            "with an aggregate, every item of the select list must be an aggregate or a constant",
        ));
    }
    Ok(Plan {
        items: bound_items,
        condition,
        aggs: b.aggs,
        limit: query.limit,
        now: datetime::now(),
    })
}

// ---------------------------------------------------------------------------
// Evaluation.

/// Follow `steps` into `v`; `None` is MISSING.
pub fn walk<'v>(v: &'v Value, steps: &[Step]) -> Option<&'v Value> {
    let mut cur = v;
    for step in steps {
        cur = match (step, cur) {
            (Step::Key { name, exact }, Value::Struct(fields)) => {
                let hit = fields.iter().find(|(k, _)| k == name).or_else(|| {
                    (!exact)
                        .then(|| fields.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)))
                        .flatten()
                });
                &hit?.1
            }
            (Step::Index(i), Value::List(items)) => items.get(usize::try_from(*i).ok()?)?,
            _ => return None,
        };
    }
    Some(cur)
}

fn number(v: &Value, what: &str) -> SelectResult<Value> {
    v.as_number().ok_or_else(|| {
        err(
            "InvalidDataType",
            format!("{} is not a number ({what})", v.describe()),
        )
    })
}

fn overflow() -> SelectError {
    err("IntegerOverflow", "the result is out of the integer range")
}

fn arith(op: BinOp, a: &Value, b: &Value) -> SelectResult<Value> {
    if a.is_null() || b.is_null() {
        return Ok(Value::Null);
    }
    let what = match op {
        BinOp::Add => "+",
        BinOp::Sub => "-",
        BinOp::Mul => "*",
        BinOp::Div => "/",
        _ => "%",
    };
    let (x, y) = (number(a, what)?, number(b, what)?);
    let div_zero = || err("ExternalEvalException", "division by zero");
    Ok(match (x, y) {
        (Value::Int(x), Value::Int(y)) => Value::Int(match op {
            BinOp::Add => x.checked_add(y).ok_or_else(overflow)?,
            BinOp::Sub => x.checked_sub(y).ok_or_else(overflow)?,
            BinOp::Mul => x.checked_mul(y).ok_or_else(overflow)?,
            BinOp::Div if y == 0 => return Err(div_zero()),
            BinOp::Div => x.checked_div(y).ok_or_else(overflow)?,
            _ if y == 0 => return Err(div_zero()),
            _ => x.checked_rem(y).ok_or_else(overflow)?,
        }),
        (x, y) => {
            let (x, y) = (
                x.as_f64().unwrap_or(f64::NAN),
                y.as_f64().unwrap_or(f64::NAN),
            );
            Value::Float(match op {
                BinOp::Add => x + y,
                BinOp::Sub => x - y,
                BinOp::Mul => x * y,
                BinOp::Div if y == 0.0 => return Err(div_zero()),
                BinOp::Div => x / y,
                _ if y == 0.0 => return Err(div_zero()),
                _ => x % y,
            })
        }
    })
}

fn bool_of(o: Option<bool>) -> Value {
    o.map_or(Value::Null, Value::Bool)
}

fn compare_op(op: BinOp, a: &Value, b: &Value) -> Value {
    match op {
        BinOp::Eq => bool_of(equals(a, b)),
        BinOp::Ne => bool_of(equals(a, b).map(|e| !e)),
        _ => bool_of(compare(a, b).map(|o| match op {
            BinOp::Lt => o == Ordering::Less,
            BinOp::Le => o != Ordering::Greater,
            BinOp::Gt => o == Ordering::Greater,
            _ => o != Ordering::Less,
        })),
    }
}

/// SQL LIKE: `%` any run, `_` one character; `escape` makes the next one
/// literal. As RGW, `[...]` is one character of a set (`[a-z]`, `[xyz]`,
/// `[^0-9]`); a `[` without its `]` is itself.
pub fn like(text: &str, pattern: &str, escape: Option<char>) -> SelectResult<bool> {
    #[derive(Clone, PartialEq)]
    enum P {
        Any,
        One,
        Ch(char),
        /// Ranges, and whether the set is negated.
        Set(Vec<(char, char)>, bool),
    }
    let mut pat = Vec::new();
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        i += 1;
        if Some(c) == escape {
            match chars.get(i) {
                Some(&n) => {
                    pat.push(P::Ch(n));
                    i += 1;
                }
                None => {
                    return Err(err(
                        "EvaluatorLikePatternInvalidEscapeSequence",
                        "the LIKE pattern ends with its escape character",
                    ));
                }
            }
        } else if c == '%' {
            if pat.last() != Some(&P::Any) {
                pat.push(P::Any);
            }
        } else if c == '_' {
            pat.push(P::One);
        } else if c == '['
            && let Some(close) = chars[i..].iter().skip(1).position(|&x| x == ']')
        {
            // The first character may be `]` itself; `close` counts from
            // the one after it.
            let body = &chars[i..=i + close];
            i += close + 2;
            let (negated, body) = match body.first() {
                Some('^' | '!') if body.len() > 1 => (true, &body[1..]),
                _ => (false, body),
            };
            let mut ranges = Vec::new();
            let mut j = 0;
            while j < body.len() {
                if j + 2 < body.len() && body[j + 1] == '-' {
                    ranges.push((body[j], body[j + 2]));
                    j += 3;
                } else {
                    ranges.push((body[j], body[j]));
                    j += 1;
                }
            }
            pat.push(P::Set(ranges, negated));
        } else {
            pat.push(P::Ch(c));
        }
    }
    let one = |p: &P, ch: char| match p {
        P::One => true,
        P::Ch(c) => *c == ch,
        P::Set(ranges, negated) => {
            ranges.iter().any(|(lo, hi)| (*lo..=*hi).contains(&ch)) != *negated
        }
        P::Any => false,
    };
    // Greedy match with one backtrack point per `%`: linear in practice.
    let t: Vec<char> = text.chars().collect();
    let (mut ti, mut pi) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while ti < t.len() {
        match pat.get(pi) {
            Some(P::Any) => {
                star = Some((pi, ti));
                pi += 1;
            }
            Some(p) if one(p, t[ti]) => {
                ti += 1;
                pi += 1;
            }
            _ => match star {
                Some((sp, st)) => {
                    pi = sp + 1;
                    ti = st + 1;
                    star = Some((sp, st + 1));
                }
                None => return Ok(false),
            },
        }
    }
    Ok(pat[pi..].iter().all(|p| *p == P::Any))
}

fn text_arg(v: &Value, f: &str) -> SelectResult<String> {
    match v {
        Value::Str(s) => Ok(s.clone()),
        Value::List(_) | Value::Struct(_) => Err(err(
            "IncorrectSqlFunctionArgumentType",
            format!("{f} takes a string, not {}", v.describe()),
        )),
        other => Ok(other.to_text()),
    }
}

fn int_arg(v: &Value, f: &str) -> SelectResult<i64> {
    match v.cast(CastType::Int) {
        Ok(Value::Int(i)) => Ok(i),
        _ => Err(err(
            "IncorrectSqlFunctionArgumentType",
            format!("{f} takes an integer, not {}", v.describe()),
        )),
    }
}

fn ts_arg(v: &Value, f: &str) -> SelectResult<Ts> {
    match v {
        Value::Timestamp(t) => Ok(*t),
        Value::Str(s) => datetime::parse_timestamp(s),
        _ => Err(err(
            "IncorrectSqlFunctionArgumentType",
            format!("{f} takes a timestamp, not {}", v.describe()),
        )),
    }
}

/// `SUBSTRING(s, start [, len])`, 1-based; the part of `[start, start+len)`
/// inside the string.
fn substring(s: &str, start: i64, len: Option<i64>) -> SelectResult<String> {
    let chars: Vec<char> = s.chars().collect();
    let n = chars.len() as i64;
    let end = match len {
        Some(l) if l < 0 => {
            return Err(err(
                "InvalidArgument",
                "SUBSTRING's length must not be negative",
            ));
        }
        Some(l) => start.saturating_add(l),
        None => n + 1,
    };
    let from = start.max(1);
    let to = end.min(n + 1);
    if to <= from {
        return Ok(String::new());
    }
    Ok(chars[(from - 1) as usize..(to - 1) as usize]
        .iter()
        .collect())
}

impl Plan {
    /// Whether the record passes WHERE.
    pub fn passes(&self, rec: Rec<'_>) -> SelectResult<bool> {
        match &self.condition {
            None => Ok(true),
            Some(c) => Ok(self.eval(c, rec, &[])?.truth()? == Some(true)),
        }
    }

    /// Evaluate `e` on `rec`; `aggs` holds the aggregates' results once the
    /// scan is done.
    pub fn eval(&self, e: &Expr, rec: Rec<'_>, aggs: &[Value]) -> SelectResult<Value> {
        let ev = |x: &Expr| self.eval(x, rec, aggs);
        Ok(match e {
            Expr::Lit(v) => v.clone(),
            Expr::Field(i, rest) => match rec {
                Rec::Fields(fields) => match fields.get(*i) {
                    Some(f) if rest.is_empty() => Value::Str(f.clone()),
                    _ => Value::Missing,
                },
                Rec::Value(v) => match v {
                    Value::Struct(cols) => cols
                        .get(*i)
                        .and_then(|(_, c)| walk(c, rest))
                        .cloned()
                        .unwrap_or(Value::Missing),
                    _ => Value::Missing,
                },
            },
            Expr::Path(steps) => match rec {
                Rec::Value(v) => {
                    // `_1`: the record, unless it has a field `_1`.
                    let found = walk(v, steps).or_else(|| match steps.first() {
                        Some(Step::Key { name, .. }) if name == "_1" => walk(v, &steps[1..]),
                        _ => None,
                    });
                    found.cloned().unwrap_or(Value::Missing)
                }
                Rec::Fields(_) => Value::Missing,
            },
            Expr::Record => match rec {
                Rec::Value(v) => v.clone(),
                Rec::Fields(fields) => Value::Struct(
                    fields
                        .iter()
                        .enumerate()
                        .map(|(i, f)| (format!("_{}", i + 1), Value::Str(f.clone())))
                        .collect(),
                ),
            },
            Expr::Name(steps) => {
                return Err(SelectError::internal(format!("unbound name {steps:?}")));
            }
            Expr::Neg(a) => {
                let v = ev(a)?;
                if v.is_null() {
                    return Ok(Value::Null);
                }
                match number(&v, "-")? {
                    Value::Int(i) => Value::Int(i.checked_neg().ok_or_else(overflow)?),
                    n => Value::Float(-n.as_f64().unwrap_or(f64::NAN)),
                }
            }
            Expr::Not(a) => bool_of(ev(a)?.truth()?.map(|b| !b)),
            Expr::Bin(op, a, b) => {
                let (x, y) = (ev(a)?, ev(b)?);
                match op {
                    BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::Div | BinOp::Mod => {
                        arith(*op, &x, &y)?
                    }
                    BinOp::Concat => {
                        if x.is_null() || y.is_null() {
                            Value::Null
                        } else {
                            Value::Str(x.to_text() + &y.to_text())
                        }
                    }
                    _ => compare_op(*op, &x, &y),
                }
            }
            Expr::And(a, b) => {
                let x = ev(a)?.truth()?;
                if x == Some(false) {
                    return Ok(Value::Bool(false));
                }
                match (x, ev(b)?.truth()?) {
                    (_, Some(false)) => Value::Bool(false),
                    (Some(true), Some(true)) => Value::Bool(true),
                    _ => Value::Null,
                }
            }
            Expr::Or(a, b) => {
                let x = ev(a)?.truth()?;
                if x == Some(true) {
                    return Ok(Value::Bool(true));
                }
                match (x, ev(b)?.truth()?) {
                    (_, Some(true)) => Value::Bool(true),
                    (Some(false), Some(false)) => Value::Bool(false),
                    _ => Value::Null,
                }
            }
            Expr::Like {
                expr,
                pattern,
                escape,
                negated,
            } => {
                let (v, p) = (ev(expr)?, ev(pattern)?);
                let esc = match escape {
                    Some(x) => {
                        let e = ev(x)?;
                        let s = text_arg(&e, "ESCAPE")?;
                        let mut it = s.chars();
                        match (it.next(), it.next()) {
                            (Some(c), None) => Some(c),
                            _ => {
                                return Err(err(
                                    "LikeInvalidInputs",
                                    "ESCAPE takes a single character",
                                ));
                            }
                        }
                    }
                    None => None,
                };
                if v.is_null() || p.is_null() {
                    return Ok(Value::Null);
                }
                let m = like(&text_arg(&v, "LIKE")?, &text_arg(&p, "LIKE")?, esc)?;
                Value::Bool(m != *negated)
            }
            Expr::Between {
                expr,
                low,
                high,
                negated,
            } => {
                let (v, lo, hi) = (ev(expr)?, ev(low)?, ev(high)?);
                let ge = compare(&v, &lo).map(|o| o != Ordering::Less);
                let le = compare(&v, &hi).map(|o| o != Ordering::Greater);
                let r = match (ge, le) {
                    (Some(false), _) | (_, Some(false)) => Some(false),
                    (Some(true), Some(true)) => Some(true),
                    _ => None,
                };
                bool_of(r.map(|b| b != *negated))
            }
            Expr::In {
                expr,
                list,
                negated,
            } => {
                let v = ev(expr)?;
                let mut r = Some(false);
                for x in list {
                    match equals(&v, &ev(x)?) {
                        Some(true) => {
                            r = Some(true);
                            break;
                        }
                        None => r = None,
                        Some(false) => {}
                    }
                }
                bool_of(r.map(|b| b != *negated))
            }
            Expr::Is {
                expr,
                what,
                negated,
            } => {
                let v = ev(expr)?;
                let r = match what {
                    IsWhat::Null => v.is_null(),
                    IsWhat::Missing => matches!(v, Value::Missing),
                    IsWhat::True => v.truth().ok().flatten() == Some(true),
                    IsWhat::False => v.truth().ok().flatten() == Some(false),
                };
                Value::Bool(r != *negated)
            }
            Expr::Case {
                operand,
                whens,
                otherwise,
            } => {
                let subject = match operand {
                    Some(o) => Some(ev(o)?),
                    None => None,
                };
                for (w, t) in whens {
                    let hit = match &subject {
                        Some(s) => equals(s, &ev(w)?) == Some(true),
                        None => ev(w)?.truth()? == Some(true),
                    };
                    if hit {
                        return ev(t);
                    }
                }
                match otherwise {
                    Some(x) => ev(x)?,
                    None => Value::Null,
                }
            }
            Expr::Cast(a, ty) => ev(a)?.cast(*ty)?,
            Expr::Call(f, args) => self.call(*f, args, rec, aggs)?,
            Expr::Agg(_, _, slot) => aggs.get(*slot).cloned().unwrap_or(Value::Null),
        })
    }

    fn call(&self, f: Func, args: &[Expr], rec: Rec<'_>, aggs: &[Value]) -> SelectResult<Value> {
        if f == Func::Coalesce {
            for a in args {
                let v = self.eval(a, rec, aggs)?;
                if !v.is_null() {
                    return Ok(v);
                }
            }
            return Ok(Value::Null);
        }
        if f == Func::UtcNow {
            return Ok(Value::Timestamp(self.now));
        }
        let vals = args
            .iter()
            .map(|a| self.eval(a, rec, aggs))
            .collect::<SelectResult<Vec<_>>>()?;
        if f == Func::NullIf {
            return Ok(match equals(&vals[0], &vals[1]) {
                Some(true) => Value::Null,
                _ => vals[0].clone(),
            });
        }
        if vals.iter().any(Value::is_null) {
            return Ok(Value::Null);
        }
        let name = f.name();
        Ok(match f {
            Func::Lower => Value::Str(text_arg(&vals[0], name)?.to_lowercase()),
            Func::Upper => Value::Str(text_arg(&vals[0], name)?.to_uppercase()),
            Func::CharLength => Value::Int(text_arg(&vals[0], name)?.chars().count() as i64),
            Func::Substring => {
                let s = text_arg(&vals[0], name)?;
                let start = int_arg(&vals[1], name)?;
                let len = match vals.get(2) {
                    Some(l) => Some(int_arg(l, name)?),
                    None => None,
                };
                Value::Str(substring(&s, start, len)?)
            }
            Func::Trim(how) => {
                let s = text_arg(&vals[0], name)?;
                let set: Vec<char> = match vals.get(1) {
                    Some(c) => text_arg(c, name)?.chars().collect(),
                    None => vec![' '],
                };
                let pred = |c: char| set.contains(&c);
                Value::Str(
                    match how {
                        TrimWhere::Both => s.trim_matches(pred),
                        TrimWhere::Leading => s.trim_start_matches(pred),
                        TrimWhere::Trailing => s.trim_end_matches(pred),
                    }
                    .to_string(),
                )
            }
            Func::ToTimestamp => Value::Timestamp(ts_arg(&vals[0], name)?),
            Func::ToString => {
                let ts = ts_arg(&vals[0], name)?;
                Value::Str(datetime::to_string(&ts, &text_arg(&vals[1], name)?)?)
            }
            Func::Extract(part) => Value::Int(datetime::extract(part, &ts_arg(&vals[0], name)?)),
            Func::DateAdd(part) => {
                let n = int_arg(&vals[0], name)?;
                Value::Timestamp(datetime::date_add(part, n, &ts_arg(&vals[1], name)?)?)
            }
            Func::DateDiff(part) => Value::Int(datetime::date_diff(
                part,
                &ts_arg(&vals[0], name)?,
                &ts_arg(&vals[1], name)?,
            )?),
            Func::Coalesce | Func::NullIf | Func::UtcNow => unreachable!("handled above"),
        })
    }
}

// ---------------------------------------------------------------------------
// Aggregates.

/// One aggregate's running state.
#[derive(Debug, Clone)]
pub enum Acc {
    Count(i64),
    /// An integer sum until a float (or an overflow) makes it a float one.
    Sum {
        int: i64,
        float: f64,
        is_float: bool,
        any: bool,
    },
    Avg {
        sum: f64,
        n: i64,
    },
    Min(Option<Value>),
    Max(Option<Value>),
}

/// MIN/MAX order: numbers (CSV text read as numbers) by value, else as
/// [`compare`] has it.
fn agg_order(a: &Value, b: &Value) -> Option<Ordering> {
    if let (Some(x), Some(y)) = (a.as_number(), b.as_number()) {
        return compare(&x, &y);
    }
    compare(a, b)
}

impl Acc {
    pub fn new(agg: Agg) -> Self {
        match agg {
            Agg::Count => Self::Count(0),
            Agg::Sum => Self::Sum {
                int: 0,
                float: 0.0,
                is_float: false,
                any: false,
            },
            Agg::Avg => Self::Avg { sum: 0.0, n: 0 },
            Agg::Min => Self::Min(None),
            Agg::Max => Self::Max(None),
        }
    }

    /// Take one value in (`None`: a row, for `COUNT(*)`).
    pub fn add(&mut self, v: Option<Value>) -> SelectResult<()> {
        let Some(v) = v else {
            if let Self::Count(n) = self {
                *n += 1;
            }
            return Ok(());
        };
        if v.is_null() {
            return Ok(());
        }
        match self {
            Self::Count(n) => *n += 1,
            Self::Sum {
                int,
                float,
                is_float,
                any,
            } => {
                *any = true;
                match number(&v, "SUM")? {
                    Value::Int(i) if !*is_float => match int.checked_add(i) {
                        Some(s) => *int = s,
                        None => {
                            *is_float = true;
                            *float = *int as f64 + i as f64;
                        }
                    },
                    n => {
                        if !*is_float {
                            *is_float = true;
                            *float = *int as f64;
                        }
                        *float += n.as_f64().unwrap_or(f64::NAN);
                    }
                }
            }
            Self::Avg { sum, n } => {
                *sum += number(&v, "AVG")?.as_f64().unwrap_or(f64::NAN);
                *n += 1;
            }
            Self::Min(cur) => {
                if cur
                    .as_ref()
                    .is_none_or(|c| agg_order(&v, c) == Some(Ordering::Less))
                {
                    *cur = Some(v);
                }
            }
            Self::Max(cur) => {
                if cur
                    .as_ref()
                    .is_none_or(|c| agg_order(&v, c) == Some(Ordering::Greater))
                {
                    *cur = Some(v);
                }
            }
        }
        Ok(())
    }

    pub fn result(self) -> Value {
        match self {
            Self::Count(n) => Value::Int(n),
            Self::Sum { any: false, .. } | Self::Avg { n: 0, .. } => Value::Null,
            Self::Sum {
                int,
                float,
                is_float,
                ..
            } => {
                if is_float {
                    Value::Float(float)
                } else {
                    Value::Int(int)
                }
            }
            Self::Avg { sum, n } => Value::Float(sum / n as f64),
            Self::Min(v) | Self::Max(v) => v.unwrap_or(Value::Null),
        }
    }
}

/// The aggregates of a scan.
pub struct Aggregator {
    accs: Vec<Acc>,
}

impl Aggregator {
    pub fn new(plan: &Plan) -> Self {
        Self {
            accs: plan.aggs.iter().map(|(a, _)| Acc::new(*a)).collect(),
        }
    }

    /// Take in a record that passed WHERE.
    pub fn add(&mut self, plan: &Plan, rec: Rec<'_>) -> SelectResult<()> {
        for ((_, arg), acc) in plan.aggs.iter().zip(self.accs.iter_mut()) {
            let v = match arg {
                Some(a) => Some(plan.eval(a, rec, &[])?),
                None => None,
            };
            acc.add(v)?;
        }
        Ok(())
    }

    pub fn results(self) -> Vec<Value> {
        self.accs.into_iter().map(Acc::result).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::super::sql::parse;
    use super::*;

    fn fields(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|s| s.to_string()).collect()
    }

    /// Run `sql` over CSV rows (no header); the rows out as text.
    fn run_csv(sql: &str, header: Option<&[&str]>, rows: &[&[&str]]) -> SelectResult<Vec<String>> {
        let header = header.map(fields);
        let plan = bind(&parse(sql)?, Schema::Csv(header.as_deref()))?;
        let rows: Vec<Vec<String>> = rows.iter().map(|r| fields(r)).collect();
        let mut out = Vec::new();
        let mut agg = Aggregator::new(&plan);
        for r in &rows {
            let rec = Rec::Fields(r);
            if !plan.passes(rec)? {
                continue;
            }
            if plan.aggregates() {
                agg.add(&plan, rec)?;
                continue;
            }
            let line = match &plan.items {
                None => r.join(","),
                Some(items) => items
                    .iter()
                    .map(|(e, _)| plan.eval(e, rec, &[]).map(|v| v.to_text()))
                    .collect::<SelectResult<Vec<_>>>()?
                    .join(","),
            };
            out.push(line);
            if plan.limit.is_some_and(|l| out.len() as u64 >= l) {
                break;
            }
        }
        if plan.aggregates() {
            let res = agg.results();
            let empty: Vec<String> = Vec::new();
            out.push(
                plan.items
                    .as_ref()
                    .unwrap()
                    .iter()
                    .map(|(e, _)| plan.eval(e, Rec::Fields(&empty), &res).map(|v| v.to_text()))
                    .collect::<SelectResult<Vec<_>>>()?
                    .join(","),
            );
        }
        Ok(out)
    }

    const ROWS: &[&[&str]] = &[&["1", "10", "a"], &["2", "20", "bb"], &["3", "", "ccc"]];

    #[test]
    fn where_and_projection() {
        assert_eq!(
            run_csv("select _3, _1 from s3object where _1 > 1", None, ROWS).unwrap(),
            ["bb,2", "ccc,3"]
        );
        assert_eq!(
            run_csv("select * from s3object s where s._2 = ''", None, ROWS).unwrap(),
            ["3,,ccc"]
        );
        assert_eq!(
            run_csv(
                "select int(_1) * 2 + 1, _1 / 2, _1 % 2, -_1, _3 || '!' from s3object limit 1",
                None,
                ROWS
            )
            .unwrap(),
            ["3,0,1,-1,a!"]
        );
        assert_eq!(
            run_csv(
                "select cast(_1 as float) / 2 from s3object where _1 = 3",
                None,
                ROWS
            )
            .unwrap(),
            ["1.5"]
        );
    }

    #[test]
    fn header_names_and_aliases() {
        let h: &[&str] = &["Id", "Score", "Name"];
        assert_eq!(
            run_csv(
                "select name, \"Score\" from s3object where id = 2",
                Some(h),
                ROWS
            )
            .unwrap(),
            ["bb,20"]
        );
        // Aliases in later items and WHERE (RGW).
        assert_eq!(
            run_csv(
                "select int(_1) as a1, int(_1) * 10 as a2, a1 + a2 as a3 from s3object where a3 > 12",
                None,
                ROWS
            )
            .unwrap(),
            ["2,20,22", "3,30,33"]
        );
        let e = run_csv("select nosuch from s3object", Some(h), ROWS).unwrap_err();
        assert_eq!(e.code, "MissingHeaders");
        let e = run_csv(
            "select int(_1) as a1, a1 + a3 as a2, a2 + 1 as a3 from s3object",
            None,
            ROWS,
        )
        .unwrap_err();
        assert!(e.message.contains("cyclic reference to alias"), "{e}");
        assert_eq!(
            run_csv("select _0 from s3object", None, ROWS)
                .unwrap_err()
                .code,
            "InvalidColumnIndex"
        );
        // A quoted name that is no column is a string (RGW).
        assert_eq!(
            run_csv(
                "select lower(\"AB12cd$$\") from s3object limit 1",
                None,
                ROWS
            )
            .unwrap(),
            ["ab12cd$$"]
        );
        // `"_b"` too: a quoted `_N` is no position either.
        assert_eq!(
            run_csv("select _1 from s3object where _3 like \"_b\"", None, ROWS).unwrap(),
            ["2"]
        );
    }

    #[test]
    fn aggregates() {
        assert_eq!(
            run_csv(
                "select count(*), count(_2), sum(_1), avg(_1), min(_2), max(_3), min(int(_1)) + 1 from s3object",
                None,
                ROWS
            )
            .unwrap(),
            ["3,3,6,2.0,,ccc,2"]
        );
        // Numbers in text order as numbers.
        let rows: &[&[&str]] = &[&["9"], &["10"], &["100"]];
        assert_eq!(
            run_csv("select min(_1), max(_1) from s3object", None, rows).unwrap(),
            ["9,100"]
        );
        assert_eq!(
            run_csv(
                "select count(*), sum(_1), avg(_1) from s3object where _1 > 1000",
                None,
                rows
            )
            .unwrap(),
            ["0,,"]
        );
        assert_eq!(
            run_csv("select _1, count(*) from s3object", None, rows)
                .unwrap_err()
                .code,
            "ParseUnsupportedSyntax"
        );
        assert_eq!(
            run_csv("select _1 from s3object where count(*) > 1", None, rows)
                .unwrap_err()
                .code,
            "ParseUnsupportedSyntax"
        );
    }

    #[test]
    fn three_valued_logic() {
        let rows: &[&[&str]] = &[&["1", "1"], &["1", "2"]];
        // nullif(a, b) IS NULL exactly when a = b.
        assert_eq!(
            run_csv(
                "select (nullif(_1, _2) is null), (_1 = _2) from s3object",
                None,
                rows
            )
            .unwrap(),
            ["true,true", "false,false"]
        );
        assert_eq!(
            run_csv(
                "select count(*) from s3object where (nullif(_1, _1) and _1 = _2) is not null",
                None,
                rows
            )
            .unwrap(),
            ["1"]
        );
        assert_eq!(
            run_csv(
                "select coalesce(null, nullif(_1, _1), _2) from s3object",
                None,
                rows
            )
            .unwrap(),
            ["1", "2"]
        );
        assert_eq!(
            run_csv(
                "select _2 in (2, null), _2 not in (3), _2 between 2 and 3 from s3object",
                None,
                rows
            )
            .unwrap(),
            [",true,false", "true,true,true"]
        );
    }

    #[test]
    fn case_and_strings() {
        let rows: &[&[&str]] = &[&["150", "   aeiou  "], &["250", "x"], &["5", "y"]];
        assert_eq!(
            run_csv(
                "select case when cast(_1 as int) > 100 and cast(_1 as int) < 200 then '(100-200)' \
                 when cast(_1 as int) > 200 then '(200-)' else 'NONE' end, \
                 case _2 when 'x' then 1 else 0 end from s3object",
                None,
                rows
            )
            .unwrap(),
            ["(100-200),0", "(200-),1", "NONE,0"]
        );
        assert_eq!(
            run_csv(
                "select trim(_2), trim(leading from _2), trim(trailing from _2), trim(both 'xy' from 'xyzyx'), \
                 char_length(_2), upper(substring(_2 from 4 for 3)), substring('123456789', 0), substring('123456789', -4, 6) \
                 from s3object limit 1",
                None,
                rows
            )
            .unwrap(),
            ["aeiou,aeiou  ,   aeiou,z,10,AEI,123456789,1"]
        );
    }

    #[test]
    fn like_patterns() {
        assert!(like("cbcdxyz", "cbcd%", None).unwrap());
        assert!(like("abc", "_b_", None).unwrap());
        assert!(!like("abcd", "_b_", None).unwrap());
        assert!(like("a%b", "a!%b", Some('!')).unwrap());
        assert!(!like("axb", "a!%b", Some('!')).unwrap());
        assert!(like("aeio_", "%aeio$_", Some('$')).unwrap());
        assert!(!like("aeiox", "%aeio$_", Some('$')).unwrap());
        assert!(like("xx_ar", "%_ar", None).unwrap());
        assert!(like("", "%", None).unwrap());
        assert!(like("mississippi", "%iss%ppi", None).unwrap());
        // RGW's sets.
        assert!(like("vwxyz", "%y[y-z]", None).unwrap());
        assert!(!like("vwxya", "%y[y-z]", None).unwrap());
        assert!(like("a]", "a[]]", None).unwrap());
        assert!(like("b7", "b[^a-z]", None).unwrap());
        assert!(!like("bc", "b[^a-z]", None).unwrap());
        assert!(like("[x", "[x", None).unwrap());
        assert!(like("[x]", "![x]", Some('!')).unwrap());
        assert_eq!(
            like("a", "a!", Some('!')).unwrap_err().code,
            "EvaluatorLikePatternInvalidEscapeSequence"
        );
    }

    #[test]
    fn dates() {
        let rows: &[&[&str]] = &[&["19550612T101010Z"]];
        assert_eq!(
            run_csv(
                "select extract(year from to_timestamp(_1)), cast(to_string(to_timestamp(_1), 'x') as int), \
                 date_diff(month, to_timestamp(_1), date_add(month, 2, to_timestamp(_1))), \
                 to_timestamp(_1), date_diff(hour, utcnow(), date_add(day, 1, utcnow())) from s3object",
                None,
                rows
            )
            .unwrap(),
            ["1955,0,2,1955-06-12T10:10:10Z,24"]
        );
    }

    #[test]
    fn json_paths() {
        let plan = bind(
            &parse("select _1.c1, s.a.b[1], s.\"A\" from s3object[*].root s").unwrap(),
            Schema::Json,
        );
        // `s` is the FROM alias: the `_1` and `s.` paths are into the record.
        let plan = plan.unwrap();
        let rec = Value::Struct(vec![
            ("c1".into(), Value::Int(7)),
            (
                "a".into(),
                Value::Struct(vec![(
                    "b".into(),
                    Value::List(vec![Value::Int(1), Value::Int(2)]),
                )]),
            ),
            ("A".into(), Value::Str("upper".into())),
        ]);
        let items = plan.items.as_ref().unwrap();
        let got: Vec<Value> = items
            .iter()
            .map(|(e, _)| plan.eval(e, Rec::Value(&rec), &[]).unwrap())
            .collect();
        assert_eq!(
            got,
            [Value::Int(7), Value::Int(2), Value::Str("upper".into())]
        );
        let names: Vec<&str> = items.iter().map(|(_, n)| n.as_str()).collect();
        assert_eq!(names, ["c1", "_2", "A"]);
    }

    #[test]
    fn errors_while_evaluating() {
        let rows: &[&[&str]] = &[&["abc", "0"]];
        assert_eq!(
            run_csv("select _1 + 1 from s3object", None, rows)
                .unwrap_err()
                .code,
            "InvalidDataType"
        );
        assert_eq!(
            run_csv("select 1 / _2 from s3object", None, rows)
                .unwrap_err()
                .code,
            "ExternalEvalException"
        );
        assert_eq!(
            run_csv("select cast(_1 as int) from s3object", None, rows)
                .unwrap_err()
                .code,
            "CastFailed"
        );
        assert_eq!(
            run_csv("select 9223372036854775807 + 1 from s3object", None, rows)
                .unwrap_err()
                .code,
            "IntegerOverflow"
        );
    }
}
