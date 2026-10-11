//! The SQL of S3 Select: tokens, the statement's tree, and its parser.
//!
//! ```text
//! SELECT * | item [, item ...]       item: expression [[AS] alias]
//! FROM S3Object[*][path] [[AS] alias]
//! [WHERE condition] [LIMIT n] [;]
//! ```
//!
//! Precedence, loosest first (as PostgreSQL has it): OR; AND; NOT; IS;
//! comparisons (`=`, `!=`, `<>`, `<`, `<=`, `>`, `>=`, left-associative, so
//! `a = b = true` is `(a = b) = true`); LIKE, BETWEEN, IN; `||`; `+ -`;
//! `* / %`; unary `-`.
//!
//! Besides AWS's dialect it takes what ceph's s3-tests write for RGW, where
//! AWS would refuse the text or leave it undefined: `"..."` where no column
//! has that name is a string (see `bind`), `FROM stdin` names the object,
//! `INT(x)` and `FLOAT(x)` cast, and a select-list alias can be used in
//! other items and in WHERE. Where RGW gives a valid AWS statement another
//! meaning (`[a-z]` in LIKE, a FROM path ending on an array), AWS's holds.

use super::datetime::DatePart;
use super::error::{SelectError, SelectResult};
use super::value::{CastType, Value};

/// Longest SQL expression accepted, as AWS (256 KB).
pub const MAX_EXPRESSION: usize = 256 * 1024;

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    /// A bare word: a keyword, a function, a column or an alias.
    Word(String),
    /// `"..."`: a case-sensitive name (or, failing one, a string).
    Quoted(String),
    /// `'...'`
    Str(String),
    /// `` `...` ``: an Ion literal (a timestamp or a number).
    Ion(String),
    Int(i64),
    Float(f64),
    Star,
    Comma,
    Dot,
    LParen,
    RParen,
    LBracket,
    RBracket,
    Semicolon,
    Op(&'static str),
    Eof,
}

impl Tok {
    fn describe(&self) -> String {
        match self {
            Self::Word(w) => format!("'{w}'"),
            Self::Quoted(w) => format!("\"{w}\""),
            Self::Str(s) => format!("'{s}'"),
            Self::Ion(s) => format!("`{s}`"),
            Self::Int(i) => i.to_string(),
            Self::Float(f) => f.to_string(),
            Self::Star => "'*'".into(),
            Self::Comma => "','".into(),
            Self::Dot => "'.'".into(),
            Self::LParen => "'('".into(),
            Self::RParen => "')'".into(),
            Self::LBracket => "'['".into(),
            Self::RBracket => "']'".into(),
            Self::Semicolon => "';'".into(),
            Self::Op(o) => format!("'{o}'"),
            Self::Eof => "the end of the expression".into(),
        }
    }
}

fn lex(sql: &str) -> SelectResult<Vec<(Tok, usize)>> {
    let b = sql.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        let at = i;
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        // `-- comment` to the end of the line.
        if c == b'-' && b.get(i + 1) == Some(&b'-') {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        let tok = match c {
            b'*' => Tok::Star,
            b',' => Tok::Comma,
            b'(' => Tok::LParen,
            b')' => Tok::RParen,
            b'[' => Tok::LBracket,
            b']' => Tok::RBracket,
            b';' => Tok::Semicolon,
            b'+' => Tok::Op("+"),
            b'-' => Tok::Op("-"),
            b'/' => Tok::Op("/"),
            b'%' => Tok::Op("%"),
            b'=' => Tok::Op("="),
            b'!' if b.get(i + 1) == Some(&b'=') => {
                i += 1;
                Tok::Op("!=")
            }
            b'<' => match b.get(i + 1) {
                Some(b'=') => {
                    i += 1;
                    Tok::Op("<=")
                }
                Some(b'>') => {
                    i += 1;
                    Tok::Op("!=")
                }
                _ => Tok::Op("<"),
            },
            b'>' => {
                if b.get(i + 1) == Some(&b'=') {
                    i += 1;
                    Tok::Op(">=")
                } else {
                    Tok::Op(">")
                }
            }
            b'|' if b.get(i + 1) == Some(&b'|') => {
                i += 1;
                Tok::Op("||")
            }
            b'\'' | b'"' | b'`' => {
                // Quoted text; the quote doubled stands for itself.
                let mut s = String::new();
                let mut j = i + 1;
                loop {
                    let Some(&d) = b.get(j) else {
                        return Err(SelectError::new(
                            "LexerInvalidLiteral",
                            format!("unterminated quoted text at character {}", at + 1),
                        ));
                    };
                    if d == c {
                        if b.get(j + 1) == Some(&c) {
                            s.push(c as char);
                            j += 2;
                            continue;
                        }
                        break;
                    }
                    // Copy a whole UTF-8 character.
                    let len = utf8_len(d);
                    s.push_str(&sql[j..j + len]);
                    j += len;
                }
                i = j;
                match c {
                    b'\'' => Tok::Str(s),
                    b'"' => Tok::Quoted(s),
                    _ => Tok::Ion(s),
                }
            }
            b'0'..=b'9' | b'.' if c != b'.' || b.get(i + 1).is_some_and(u8::is_ascii_digit) => {
                let mut j = i;
                let mut float = false;
                while j < b.len() && b[j].is_ascii_digit() {
                    j += 1;
                }
                if b.get(j) == Some(&b'.') {
                    float = true;
                    j += 1;
                    while j < b.len() && b[j].is_ascii_digit() {
                        j += 1;
                    }
                }
                if matches!(b.get(j), Some(b'e' | b'E')) {
                    let mut k = j + 1;
                    if matches!(b.get(k), Some(b'+' | b'-')) {
                        k += 1;
                    }
                    if b.get(k).is_some_and(u8::is_ascii_digit) {
                        float = true;
                        j = k;
                        while j < b.len() && b[j].is_ascii_digit() {
                            j += 1;
                        }
                    }
                }
                let text = &sql[i..j];
                i = j - 1;
                if !float && let Ok(n) = text.parse::<i64>() {
                    Tok::Int(n)
                } else {
                    Tok::Float(text.parse().map_err(|_| {
                        SelectError::new("LexerInvalidLiteral", format!("'{text}' is not a number"))
                    })?)
                }
            }
            b'.' => Tok::Dot,
            c if c.is_ascii_alphabetic() || c == b'_' || c >= 0x80 => {
                let mut j = i;
                while j < b.len()
                    && (b[j].is_ascii_alphanumeric()
                        || b[j] == b'_'
                        || b[j] == b'$'
                        || b[j] >= 0x80)
                {
                    j += 1;
                }
                let w = sql[i..j].to_string();
                i = j - 1;
                Tok::Word(w)
            }
            _ => {
                let ch = sql[i..].chars().next().unwrap_or('?');
                return Err(SelectError::new(
                    "LexerInvalidChar",
                    format!("unexpected character '{ch}' at character {}", at + 1),
                ));
            }
        };
        i += 1;
        out.push((tok, at));
    }
    out.push((Tok::Eof, sql.len()));
    Ok(out)
}

fn utf8_len(first: u8) -> usize {
    match first {
        0xf0..=0xff => 4,
        0xe0..=0xef => 3,
        0xc0..=0xdf => 2,
        _ => 1,
    }
}

// ---------------------------------------------------------------------------
// The tree.

/// One step of a path: `.name`, `."Name"`, `[n]`, `[*]`, `.*`.
#[derive(Debug, Clone, PartialEq)]
pub enum Step {
    /// A field; `exact` when it was quoted (case-sensitive).
    Key {
        name: String,
        exact: bool,
    },
    Index(i64),
    /// `[*]`: every element of an array.
    AllElements,
    /// `.*`: every value of an object.
    AllValues,
}

impl Step {
    /// Whether this key step names `key`.
    pub fn matches(&self, key: &str) -> bool {
        match self {
            Self::Key { name, exact: true } => name == key,
            Self::Key { name, exact: false } => name.eq_ignore_ascii_case(key),
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Concat,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Agg {
    Count,
    Sum,
    Avg,
    Min,
    Max,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrimWhere {
    Both,
    Leading,
    Trailing,
}

/// Scalar functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Func {
    Lower,
    Upper,
    CharLength,
    /// `SUBSTRING(s, start [, length])`
    Substring,
    /// `TRIM([where] [chars FROM] s)`: args are `[s]` or `[s, chars]`.
    Trim(TrimWhere),
    Coalesce,
    NullIf,
    ToTimestamp,
    ToString,
    Extract(DatePart),
    DateAdd(DatePart),
    DateDiff(DatePart),
    UtcNow,
}

impl Func {
    pub fn name(self) -> &'static str {
        match self {
            Self::Lower => "LOWER",
            Self::Upper => "UPPER",
            Self::CharLength => "CHAR_LENGTH",
            Self::Substring => "SUBSTRING",
            Self::Trim(_) => "TRIM",
            Self::Coalesce => "COALESCE",
            Self::NullIf => "NULLIF",
            Self::ToTimestamp => "TO_TIMESTAMP",
            Self::ToString => "TO_STRING",
            Self::Extract(_) => "EXTRACT",
            Self::DateAdd(_) => "DATE_ADD",
            Self::DateDiff(_) => "DATE_DIFF",
            Self::UtcNow => "UTCNOW",
        }
    }
}

/// What `IS [NOT]` tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsWhat {
    Null,
    Missing,
    True,
    False,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    Lit(Value),
    /// A name as written: a column, a path into the record, an alias.
    /// Resolved by `bind`.
    Name(Vec<Step>),
    Neg(Box<Expr>),
    Not(Box<Expr>),
    Bin(BinOp, Box<Expr>, Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Like {
        expr: Box<Expr>,
        pattern: Box<Expr>,
        escape: Option<Box<Expr>>,
        negated: bool,
    },
    Between {
        expr: Box<Expr>,
        low: Box<Expr>,
        high: Box<Expr>,
        negated: bool,
    },
    In {
        expr: Box<Expr>,
        list: Vec<Expr>,
        negated: bool,
    },
    Is {
        expr: Box<Expr>,
        what: IsWhat,
        negated: bool,
    },
    Case {
        operand: Option<Box<Expr>>,
        whens: Vec<(Expr, Expr)>,
        otherwise: Option<Box<Expr>>,
    },
    Cast(Box<Expr>, CastType),
    Call(Func, Vec<Expr>),
    /// An aggregate; `None` is `COUNT(*)`. The slot is its accumulator's
    /// index, given by `bind`.
    Agg(Agg, Option<Box<Expr>>, usize),
    // Bound forms (from `bind`):
    /// The record's n-th field (CSV column, Parquet top-level column), then
    /// a path into it.
    Field(usize, Vec<Step>),
    /// A path into the record (JSON), from its first step.
    Path(Vec<Step>),
    /// The record itself.
    Record,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Item {
    pub expr: Expr,
    pub alias: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Projection {
    Star,
    Items(Vec<Item>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Query {
    pub projection: Projection,
    /// Steps after `S3Object[*]`.
    pub from_path: Vec<Step>,
    pub from_alias: Option<String>,
    pub condition: Option<Expr>,
    pub limit: Option<u64>,
}

// ---------------------------------------------------------------------------
// The parser.

const RESERVED: &[&str] = &[
    "select", "from", "where", "limit", "as", "and", "or", "not", "is", "null", "missing", "true",
    "false", "like", "escape", "between", "in", "case", "when", "then", "else", "end", "cast",
];

fn is_reserved(w: &str) -> bool {
    RESERVED.iter().any(|r| r.eq_ignore_ascii_case(w))
}

struct Parser {
    toks: Vec<(Tok, usize)>,
    pos: usize,
}

fn parse_err(code: &'static str, message: impl Into<String>) -> SelectError {
    SelectError::new(code, message)
}

impl Parser {
    fn peek(&self) -> &Tok {
        &self.toks[self.pos].0
    }

    fn peek_at(&self, n: usize) -> &Tok {
        &self.toks[(self.pos + n).min(self.toks.len() - 1)].0
    }

    fn at(&self) -> usize {
        self.toks[self.pos].1 + 1
    }

    fn next(&mut self) -> Tok {
        let t = self.toks[self.pos].0.clone();
        if self.pos + 1 < self.toks.len() {
            self.pos += 1;
        }
        t
    }

    fn is_kw(&self, kw: &str) -> bool {
        matches!(self.peek(), Tok::Word(w) if w.eq_ignore_ascii_case(kw))
    }

    fn eat_kw(&mut self, kw: &str) -> bool {
        if self.is_kw(kw) {
            self.next();
            true
        } else {
            false
        }
    }

    fn eat(&mut self, t: &Tok) -> bool {
        if self.peek() == t {
            self.next();
            true
        } else {
            false
        }
    }

    fn unexpected(&self, wanted: &str) -> SelectError {
        parse_err(
            "ParseUnexpectedToken",
            format!(
                "expected {wanted}, found {} at character {}",
                self.peek().describe(),
                self.at()
            ),
        )
    }

    fn expect(&mut self, t: &Tok) -> SelectResult<()> {
        if self.eat(t) {
            Ok(())
        } else {
            Err(self.unexpected(&t.describe()))
        }
    }

    fn expect_kw(&mut self, kw: &str) -> SelectResult<()> {
        if self.eat_kw(kw) {
            Ok(())
        } else {
            Err(parse_err(
                "ParseExpectedKeyword",
                format!(
                    "expected {}, found {} at character {}",
                    kw.to_ascii_uppercase(),
                    self.peek().describe(),
                    self.at()
                ),
            ))
        }
    }

    fn statement(&mut self) -> SelectResult<Query> {
        if !self.eat_kw("select") {
            return Err(parse_err(
                "ParseUnsupportedSelect",
                "the expression must start with SELECT",
            ));
        }
        let projection = if self.eat(&Tok::Star) {
            if self.peek() == &Tok::Comma {
                return Err(parse_err(
                    "ParseAsteriskIsNotAloneInSelectList",
                    "'*' cannot be combined with other items in the select list",
                ));
            }
            Projection::Star
        } else {
            let mut items = Vec::new();
            loop {
                if self.is_kw("from") || self.peek() == &Tok::Eof {
                    return Err(parse_err("ParseEmptySelect", "the select list is empty"));
                }
                if self.peek() == &Tok::Star {
                    return Err(parse_err(
                        "ParseAsteriskIsNotAloneInSelectList",
                        "'*' cannot be combined with other items in the select list",
                    ));
                }
                let expr = self.expr()?;
                let alias = self.alias()?;
                items.push(Item { expr, alias });
                if !self.eat(&Tok::Comma) {
                    break;
                }
            }
            Projection::Items(items)
        };
        if !self.eat_kw("from") {
            return Err(parse_err(
                "ParseSelectMissingFrom",
                format!(
                    "expected FROM, found {} at character {}",
                    self.peek().describe(),
                    self.at()
                ),
            ));
        }
        let (from_path, from_alias) = self.from()?;
        let condition = if self.eat_kw("where") {
            Some(self.expr()?)
        } else {
            None
        };
        let limit = if self.eat_kw("limit") {
            match self.next() {
                Tok::Int(n) if n >= 0 => Some(n as u64),
                Tok::Op("-") => {
                    return Err(parse_err(
                        "EvaluatorNegativeLimit",
                        "LIMIT must not be negative",
                    ));
                }
                _ => {
                    self.pos -= 1;
                    return Err(parse_err(
                        "ParseExpectedNumber",
                        format!("LIMIT takes a number, at character {}", self.at()),
                    ));
                }
            }
        } else {
            None
        };
        self.eat(&Tok::Semicolon);
        if self.peek() != &Tok::Eof {
            return Err(parse_err(
                "ParseUnsupportedSyntax",
                format!(
                    "unexpected {} at character {} after the end of the statement",
                    self.peek().describe(),
                    self.at()
                ),
            ));
        }
        Ok(Query {
            projection,
            from_path,
            from_alias,
            condition,
            limit,
        })
    }

    /// `[AS] name` after a select item or the FROM source.
    fn alias(&mut self) -> SelectResult<Option<String>> {
        if self.eat_kw("as") {
            return match self.next() {
                Tok::Word(w) if !is_reserved(&w) => Ok(Some(w)),
                Tok::Quoted(w) => Ok(Some(w)),
                _ => {
                    self.pos -= 1;
                    Err(parse_err(
                        "ParseExpectedIdentForAlias",
                        format!("AS takes a name, at character {}", self.at()),
                    ))
                }
            };
        }
        match self.peek().clone() {
            Tok::Word(w) if !is_reserved(&w) => {
                self.next();
                Ok(Some(w))
            }
            _ => Ok(None),
        }
    }

    fn from(&mut self) -> SelectResult<(Vec<Step>, Option<String>)> {
        let source = matches!(self.peek(), Tok::Word(w)
            if w.eq_ignore_ascii_case("s3object") || w.eq_ignore_ascii_case("stdin"));
        if !source {
            return Err(parse_err(
                "InvalidDataSource",
                format!(
                    "the data source must be S3Object, found {} at character {}",
                    self.peek().describe(),
                    self.at()
                ),
            ));
        }
        self.next();
        // `S3Object[*]` (or `S3Object`) is the stream of records; any path
        // after it leads into each.
        let mut steps = Vec::new();
        let mut first = true;
        loop {
            match self.peek() {
                Tok::LBracket if first && self.peek_at(1) == &Tok::Star => {
                    self.next();
                    self.next();
                    self.expect(&Tok::RBracket)?;
                }
                Tok::LBracket | Tok::Dot => steps.push(self.step()?),
                _ => break,
            }
            first = false;
        }
        Ok((steps, self.alias()?))
    }

    /// One path step after a name.
    fn step(&mut self) -> SelectResult<Step> {
        match self.next() {
            Tok::Dot => match self.next() {
                Tok::Word(w) => Ok(Step::Key {
                    name: w,
                    exact: false,
                }),
                Tok::Quoted(w) => Ok(Step::Key {
                    name: w,
                    exact: true,
                }),
                Tok::Star => Ok(Step::AllValues),
                _ => {
                    self.pos -= 1;
                    Err(parse_err(
                        "ParseInvalidPathComponent",
                        format!("expected a name after '.', at character {}", self.at()),
                    ))
                }
            },
            Tok::LBracket => {
                let step = match self.next() {
                    Tok::Int(n) => Step::Index(n),
                    Tok::Star => Step::AllElements,
                    Tok::Str(s) | Tok::Quoted(s) => Step::Key {
                        name: s,
                        exact: true,
                    },
                    _ => {
                        self.pos -= 1;
                        return Err(parse_err(
                            "ParseInvalidPathComponent",
                            format!(
                                "expected an index, '*' or a name in brackets, at character {}",
                                self.at()
                            ),
                        ));
                    }
                };
                self.expect(&Tok::RBracket)?;
                Ok(step)
            }
            _ => unreachable!("step() is called on '.' or '['"),
        }
    }

    fn expr(&mut self) -> SelectResult<Expr> {
        self.or()
    }

    fn or(&mut self) -> SelectResult<Expr> {
        let mut left = self.and()?;
        while self.eat_kw("or") {
            let right = self.and()?;
            left = Expr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn and(&mut self) -> SelectResult<Expr> {
        let mut left = self.not()?;
        while self.eat_kw("and") {
            let right = self.not()?;
            left = Expr::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn not(&mut self) -> SelectResult<Expr> {
        if self.eat_kw("not") {
            return Ok(Expr::Not(Box::new(self.not()?)));
        }
        self.is()
    }

    fn is(&mut self) -> SelectResult<Expr> {
        let mut left = self.comparison()?;
        while self.eat_kw("is") {
            let negated = self.eat_kw("not");
            let what = match self.next() {
                Tok::Word(w) if w.eq_ignore_ascii_case("null") => IsWhat::Null,
                Tok::Word(w) if w.eq_ignore_ascii_case("missing") => IsWhat::Missing,
                Tok::Word(w) if w.eq_ignore_ascii_case("true") => IsWhat::True,
                Tok::Word(w) if w.eq_ignore_ascii_case("false") => IsWhat::False,
                _ => {
                    self.pos -= 1;
                    return Err(parse_err(
                        "ParseExpectedKeyword",
                        format!(
                            "IS takes NULL, MISSING, TRUE or FALSE, at character {}",
                            self.at()
                        ),
                    ));
                }
            };
            left = Expr::Is {
                expr: Box::new(left),
                what,
                negated,
            };
        }
        Ok(left)
    }

    fn comparison(&mut self) -> SelectResult<Expr> {
        let mut left = self.predicate()?;
        loop {
            let op = match self.peek() {
                Tok::Op("=") => BinOp::Eq,
                Tok::Op("!=") => BinOp::Ne,
                Tok::Op("<") => BinOp::Lt,
                Tok::Op("<=") => BinOp::Le,
                Tok::Op(">") => BinOp::Gt,
                Tok::Op(">=") => BinOp::Ge,
                _ => return Ok(left),
            };
            self.next();
            let right = self.predicate()?;
            left = Expr::Bin(op, Box::new(left), Box::new(right));
        }
    }

    fn predicate(&mut self) -> SelectResult<Expr> {
        let left = self.concat()?;
        let negated = if self.is_kw("not")
            && matches!(self.peek_at(1), Tok::Word(w)
                if ["like", "between", "in"].iter().any(|k| w.eq_ignore_ascii_case(k)))
        {
            self.next();
            true
        } else {
            false
        };
        if self.eat_kw("like") {
            let pattern = self.concat()?;
            let escape = if self.eat_kw("escape") {
                Some(Box::new(self.concat()?))
            } else {
                None
            };
            return Ok(Expr::Like {
                expr: Box::new(left),
                pattern: Box::new(pattern),
                escape,
                negated,
            });
        }
        if self.eat_kw("between") {
            let low = self.concat()?;
            self.expect_kw("and")?;
            let high = self.concat()?;
            return Ok(Expr::Between {
                expr: Box::new(left),
                low: Box::new(low),
                high: Box::new(high),
                negated,
            });
        }
        if self.eat_kw("in") {
            self.expect(&Tok::LParen)?;
            let list = self.args_until_paren()?;
            if list.is_empty() {
                return Err(parse_err(
                    "ParseExpectedExpression",
                    "IN takes a list of one or more values",
                ));
            }
            return Ok(Expr::In {
                expr: Box::new(left),
                list,
                negated,
            });
        }
        Ok(left)
    }

    fn concat(&mut self) -> SelectResult<Expr> {
        let mut left = self.additive()?;
        while self.eat(&Tok::Op("||")) {
            let right = self.additive()?;
            left = Expr::Bin(BinOp::Concat, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn additive(&mut self) -> SelectResult<Expr> {
        let mut left = self.multiplicative()?;
        loop {
            let op = match self.peek() {
                Tok::Op("+") => BinOp::Add,
                Tok::Op("-") => BinOp::Sub,
                _ => return Ok(left),
            };
            self.next();
            let right = self.multiplicative()?;
            left = Expr::Bin(op, Box::new(left), Box::new(right));
        }
    }

    fn multiplicative(&mut self) -> SelectResult<Expr> {
        let mut left = self.unary()?;
        loop {
            let op = match self.peek() {
                Tok::Star => BinOp::Mul,
                Tok::Op("/") => BinOp::Div,
                Tok::Op("%") => BinOp::Mod,
                _ => return Ok(left),
            };
            self.next();
            let right = self.unary()?;
            left = Expr::Bin(op, Box::new(left), Box::new(right));
        }
    }

    fn unary(&mut self) -> SelectResult<Expr> {
        if self.eat(&Tok::Op("-")) {
            return Ok(match self.unary()? {
                Expr::Lit(Value::Int(i)) => Expr::Lit(Value::Int(-i)),
                Expr::Lit(Value::Float(f)) => Expr::Lit(Value::Float(-f)),
                e => Expr::Neg(Box::new(e)),
            });
        }
        if self.eat(&Tok::Op("+")) {
            return self.unary();
        }
        self.primary()
    }

    /// Comma-separated expressions up to and including `)`.
    fn args_until_paren(&mut self) -> SelectResult<Vec<Expr>> {
        let mut args = Vec::new();
        if self.eat(&Tok::RParen) {
            return Ok(args);
        }
        loop {
            args.push(self.expr()?);
            if self.eat(&Tok::RParen) {
                return Ok(args);
            }
            if !self.eat(&Tok::Comma) {
                return Err(parse_err(
                    "ParseExpectedArgumentDelimiter",
                    format!(
                        "expected ',' or ')', found {} at character {}",
                        self.peek().describe(),
                        self.at()
                    ),
                ));
            }
        }
    }

    fn primary(&mut self) -> SelectResult<Expr> {
        let at = self.at();
        match self.next() {
            Tok::Int(i) => Ok(Expr::Lit(Value::Int(i))),
            Tok::Float(f) => Ok(Expr::Lit(Value::Float(f))),
            Tok::Str(s) => Ok(Expr::Lit(Value::Str(s))),
            Tok::Ion(s) => ion_literal(&s),
            Tok::LParen => {
                let e = self.expr()?;
                self.expect(&Tok::RParen)?;
                Ok(e)
            }
            Tok::Quoted(name) => self.path(Step::Key { name, exact: true }),
            Tok::Word(w) => {
                let lower = w.to_ascii_lowercase();
                match lower.as_str() {
                    "null" => return Ok(Expr::Lit(Value::Null)),
                    "missing" => return Ok(Expr::Lit(Value::Missing)),
                    "true" => return Ok(Expr::Lit(Value::Bool(true))),
                    "false" => return Ok(Expr::Lit(Value::Bool(false))),
                    "case" => return self.case(),
                    "cast" => return self.cast(),
                    _ => {}
                }
                if self.peek() == &Tok::LParen {
                    self.next();
                    return self.call(&w, &lower);
                }
                if is_reserved(&lower) {
                    return Err(parse_err(
                        "ParseUnexpectedKeyword",
                        format!(
                            "unexpected keyword {} at character {at}",
                            w.to_ascii_uppercase()
                        ),
                    ));
                }
                self.path(Step::Key {
                    name: w,
                    exact: false,
                })
            }
            Tok::Eof => Err(parse_err(
                "ParseExpectedExpression",
                "the expression ends where a value was expected",
            )),
            t => Err(parse_err(
                "ParseExpectedExpression",
                format!("expected a value, found {} at character {at}", t.describe()),
            )),
        }
    }

    /// A name and the steps after it.
    fn path(&mut self, head: Step) -> SelectResult<Expr> {
        let mut steps = vec![head];
        while matches!(self.peek(), Tok::Dot | Tok::LBracket) {
            let step = self.step()?;
            if matches!(step, Step::AllElements | Step::AllValues) {
                return Err(parse_err(
                    "ParseInvalidContextForWildcardInSelectList",
                    "a path wildcard is only allowed in FROM",
                ));
            }
            steps.push(step);
        }
        Ok(Expr::Name(steps))
    }

    fn case(&mut self) -> SelectResult<Expr> {
        let operand = if self.is_kw("when") {
            None
        } else {
            Some(Box::new(self.expr()?))
        };
        let mut whens = Vec::new();
        while self.eat_kw("when") {
            let cond = self.expr()?;
            self.expect_kw("then")?;
            whens.push((cond, self.expr()?));
        }
        if whens.is_empty() {
            return Err(parse_err(
                "ParseExpectedWhenClause",
                format!("CASE needs a WHEN, at character {}", self.at()),
            ));
        }
        let otherwise = if self.eat_kw("else") {
            Some(Box::new(self.expr()?))
        } else {
            None
        };
        self.expect_kw("end")?;
        Ok(Expr::Case {
            operand,
            whens,
            otherwise,
        })
    }

    fn cast(&mut self) -> SelectResult<Expr> {
        if !self.eat(&Tok::LParen) {
            return Err(parse_err(
                "ParseExpectedLeftParenAfterCast",
                format!("expected '(' after CAST, at character {}", self.at()),
            ));
        }
        let e = self.expr()?;
        self.expect_kw("as")?;
        let ty = self.type_name()?;
        self.expect(&Tok::RParen)?;
        Ok(Expr::Cast(Box::new(e), ty))
    }

    fn type_name(&mut self) -> SelectResult<CastType> {
        let ty = match self.next() {
            Tok::Word(w) => CastType::parse(&w),
            _ => None,
        };
        let Some(ty) = ty else {
            self.pos -= 1;
            return Err(parse_err(
                "ParseExpectedTypeName",
                format!(
                    "expected a type (INT, FLOAT, DECIMAL, STRING, BOOL, TIMESTAMP), found {} at character {}",
                    self.peek().describe(),
                    self.at()
                ),
            ));
        };
        // `DECIMAL(p, s)`, `VARCHAR(n)`: the parameters change nothing here.
        if self.eat(&Tok::LParen) {
            loop {
                match self.next() {
                    Tok::Int(_) => {}
                    _ => {
                        self.pos -= 1;
                        return Err(parse_err(
                            "ParseInvalidTypeParam",
                            format!(
                                "a type parameter must be a number, at character {}",
                                self.at()
                            ),
                        ));
                    }
                }
                if self.eat(&Tok::RParen) {
                    break;
                }
                self.expect(&Tok::Comma)?;
            }
        }
        Ok(ty)
    }

    fn date_part(&mut self) -> SelectResult<DatePart> {
        let part = match self.next() {
            Tok::Word(w) | Tok::Str(w) | Tok::Quoted(w) => DatePart::parse(&w),
            _ => None,
        };
        part.ok_or_else(|| {
            self.pos -= 1;
            parse_err(
                "ParseExpectedDatePart",
                format!(
                    "expected a date part (YEAR, MONTH, DAY, HOUR, MINUTE, SECOND, TIMEZONE_HOUR, TIMEZONE_MINUTE), at character {}",
                    self.at()
                ),
            )
        })
    }

    /// A call, after `name(`.
    fn call(&mut self, name: &str, lower: &str) -> SelectResult<Expr> {
        let agg = match lower {
            "count" => Some(Agg::Count),
            "sum" => Some(Agg::Sum),
            "avg" => Some(Agg::Avg),
            "min" => Some(Agg::Min),
            "max" => Some(Agg::Max),
            _ => None,
        };
        if let Some(agg) = agg {
            if agg == Agg::Count && self.peek() == &Tok::Star {
                self.next();
                self.expect(&Tok::RParen)?;
                return Ok(Expr::Agg(agg, None, 0));
            }
            if self.peek() == &Tok::Star {
                return Err(parse_err(
                    "ParseUnsupportedCallWithStar",
                    format!("only COUNT takes '*', not {}", name.to_ascii_uppercase()),
                ));
            }
            let args = self.args_until_paren()?;
            if args.len() != 1 {
                return Err(parse_err(
                    "ParseNonUnaryAgregateFunctionCall",
                    format!("{} takes one argument", name.to_ascii_uppercase()),
                ));
            }
            let arg = args.into_iter().next().unwrap();
            return Ok(Expr::Agg(agg, Some(Box::new(arg)), 0));
        }
        let arity = |args: &[Expr], lo: usize, hi: usize, f: &str| -> SelectResult<()> {
            if args.len() < lo || args.len() > hi {
                return Err(parse_err(
                    "IncorrectSqlFunctionArgumentType",
                    format!("{f} takes {}", plural_args(lo, hi)),
                ));
            }
            Ok(())
        };
        let func = match lower {
            "lower" => Func::Lower,
            "upper" => Func::Upper,
            "char_length" | "character_length" => Func::CharLength,
            "coalesce" => Func::Coalesce,
            "nullif" => Func::NullIf,
            "to_timestamp" => Func::ToTimestamp,
            "to_string" => Func::ToString,
            "utcnow" => Func::UtcNow,
            "substring" => return self.substring(),
            "trim" => return self.trim(),
            "extract" => {
                let part = self.date_part()?;
                self.expect_kw("from")?;
                let e = self.expr()?;
                self.expect(&Tok::RParen)?;
                return Ok(Expr::Call(Func::Extract(part), vec![e]));
            }
            "date_add" | "date_diff" => {
                let part = self.date_part()?;
                self.expect(&Tok::Comma)?;
                let args = self.args_until_paren()?;
                arity(&args, 2, 2, &name.to_ascii_uppercase())?;
                let f = if lower == "date_add" {
                    Func::DateAdd(part)
                } else {
                    Func::DateDiff(part)
                };
                return Ok(Expr::Call(f, args));
            }
            // RGW's casts.
            "int" | "float" => {
                let args = self.args_until_paren()?;
                arity(&args, 1, 1, &name.to_ascii_uppercase())?;
                let ty = if lower == "int" {
                    CastType::Int
                } else {
                    CastType::Float
                };
                return Ok(Expr::Cast(Box::new(args.into_iter().next().unwrap()), ty));
            }
            _ => {
                return Err(parse_err(
                    "UnsupportedFunction",
                    format!(
                        "{} is not a function S3 Select has",
                        name.to_ascii_uppercase()
                    ),
                ));
            }
        };
        let args = self.args_until_paren()?;
        let upper = func.name();
        match func {
            Func::Lower | Func::Upper | Func::CharLength | Func::ToTimestamp => {
                arity(&args, 1, 1, upper)?;
            }
            Func::NullIf | Func::ToString => arity(&args, 2, 2, upper)?,
            Func::Coalesce => arity(&args, 1, usize::MAX, upper)?,
            Func::UtcNow => arity(&args, 0, 0, upper)?,
            _ => {}
        }
        Ok(Expr::Call(func, args))
    }

    /// `SUBSTRING(s, start [, len])` or `SUBSTRING(s FROM start [FOR len])`.
    fn substring(&mut self) -> SelectResult<Expr> {
        let s = self.expr()?;
        let mut args = vec![s];
        if self.eat_kw("from") {
            args.push(self.expr()?);
            if self.eat_kw("for") {
                args.push(self.expr()?);
            }
            self.expect(&Tok::RParen)?;
        } else {
            self.expect(&Tok::Comma)?;
            args.extend(self.args_until_paren()?);
            if args.len() > 3 {
                return Err(parse_err(
                    "IncorrectSqlFunctionArgumentType",
                    "SUBSTRING takes 2 or 3 arguments",
                ));
            }
        }
        Ok(Expr::Call(Func::Substring, args))
    }

    /// `TRIM([[BOTH|LEADING|TRAILING] [chars] FROM] s)`.
    fn trim(&mut self) -> SelectResult<Expr> {
        let spec = if self.eat_kw("both") {
            Some(TrimWhere::Both)
        } else if self.eat_kw("leading") {
            Some(TrimWhere::Leading)
        } else if self.eat_kw("trailing") {
            Some(TrimWhere::Trailing)
        } else {
            None
        };
        let how = spec.unwrap_or(TrimWhere::Both);
        if self.eat_kw("from") {
            let s = self.expr()?;
            self.expect(&Tok::RParen)?;
            return Ok(Expr::Call(Func::Trim(how), vec![s]));
        }
        let first = self.expr()?;
        if self.eat_kw("from") {
            let s = self.expr()?;
            self.expect(&Tok::RParen)?;
            return Ok(Expr::Call(Func::Trim(how), vec![s, first]));
        }
        if spec.is_some() {
            return Err(self.unexpected("FROM"));
        }
        self.expect(&Tok::RParen)?;
        Ok(Expr::Call(Func::Trim(how), vec![first]))
    }
}

fn plural_args(lo: usize, hi: usize) -> String {
    match (lo, hi) {
        (0, 0) => "no arguments".into(),
        (1, 1) => "one argument".into(),
        (l, h) if l == h => format!("{l} arguments"),
        (l, usize::MAX) => format!("{l} or more arguments"),
        (l, h) => format!("{l} to {h} arguments"),
    }
}

/// `` `2007-02-23T12:14Z` ``, `` `1.5` ``: a timestamp or a number.
fn ion_literal(s: &str) -> SelectResult<Expr> {
    let t = s.trim();
    if let Some(n) = super::value::parse_number(t) {
        return Ok(Expr::Lit(n));
    }
    super::datetime::parse_timestamp(t)
        .map(|ts| Expr::Lit(Value::Timestamp(ts)))
        .map_err(|_| {
            SelectError::new(
                "LexerInvalidIONLiteral",
                format!("`{s}` is not an Ion timestamp or number"),
            )
        })
}

/// Parse a statement.
pub fn parse(sql: &str) -> SelectResult<Query> {
    if sql.len() > MAX_EXPRESSION {
        return Err(SelectError::new(
            "ExpressionTooLong",
            "the SQL expression is longer than 256 KB",
        ));
    }
    if sql.trim().is_empty() {
        return Err(SelectError::new(
            "MissingRequiredParameter",
            "the request has no SQL expression",
        ));
    }
    let mut p = Parser {
        toks: lex(sql)?,
        pos: 0,
    };
    p.statement()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: &str) -> Step {
        Step::Key {
            name: n.into(),
            exact: false,
        }
    }

    fn name(n: &str) -> Expr {
        Expr::Name(vec![key(n)])
    }

    fn items(q: &Query) -> &[Item] {
        match &q.projection {
            Projection::Items(i) => i,
            Projection::Star => panic!("star"),
        }
    }

    #[test]
    fn a_plain_statement() {
        let q = parse("select _1, _2 as two from s3object where _1 > 10 limit 5;").unwrap();
        assert_eq!(items(&q).len(), 2);
        assert_eq!(items(&q)[1].alias.as_deref(), Some("two"));
        assert_eq!(q.limit, Some(5));
        assert_eq!(
            q.condition,
            Some(Expr::Bin(
                BinOp::Gt,
                Box::new(name("_1")),
                Box::new(Expr::Lit(Value::Int(10)))
            ))
        );
    }

    #[test]
    fn from_takes_a_path_and_an_alias() {
        let q = parse("SELECT s.id FROM S3Object[*].Rules[*] s").unwrap();
        assert_eq!(q.from_path, vec![key("Rules"), Step::AllElements]);
        assert_eq!(q.from_alias.as_deref(), Some("s"));
        let q = parse("SELECT * FROM S3Object AS t").unwrap();
        assert!(q.from_path.is_empty());
        assert_eq!(q.from_alias.as_deref(), Some("t"));
        assert_eq!(q.projection, Projection::Star);
        let q = parse("select count(0) from stdin;").unwrap();
        assert!(q.from_alias.is_none());
    }

    #[test]
    fn precedence_is_sql_s() {
        // NOT is looser than IS; comparisons chain to the left.
        let q = parse("select * from s3object where not a is null").unwrap();
        assert!(matches!(q.condition, Some(Expr::Not(ref e)) if matches!(**e, Expr::Is { .. })));
        let q = parse("select * from s3object where trim(_1) = 'x' = true").unwrap();
        let Some(Expr::Bin(BinOp::Eq, left, right)) = q.condition else {
            panic!()
        };
        assert!(matches!(*left, Expr::Bin(BinOp::Eq, _, _)));
        assert_eq!(*right, Expr::Lit(Value::Bool(true)));
        // * before +, unary minus folded into literals.
        let q = parse("select 1 + 2 * -3 from s3object").unwrap();
        assert_eq!(
            items(&q)[0].expr,
            Expr::Bin(
                BinOp::Add,
                Box::new(Expr::Lit(Value::Int(1))),
                Box::new(Expr::Bin(
                    BinOp::Mul,
                    Box::new(Expr::Lit(Value::Int(2))),
                    Box::new(Expr::Lit(Value::Int(-3)))
                ))
            )
        );
        // a AND b OR c is (a AND b) OR c; BETWEEN's AND is its own.
        let q = parse("select * from s3object where a between 1 and 2 and b = 1 or c = 2").unwrap();
        let Some(Expr::Or(left, _)) = q.condition else {
            panic!()
        };
        assert!(matches!(*left, Expr::And(ref l, _) if matches!(**l, Expr::Between { .. })));
    }

    #[test]
    fn the_special_forms_parse() {
        for sql in [
            "select substring(_1 from 2 for 3), substring(_1, 2), substring(_1, 2, 3) from s3object",
            "select trim(_1), trim(both from _1), trim(leading 'x' from _1), trim('x' from _1) from s3object",
            "select extract(year from to_timestamp(_1)), date_add(day, 1, utcnow()), date_diff(month, a, b) from s3object",
            "select cast(_1 as decimal(10, 2)), int(_2), float(_3) from s3object",
            "select case when a > 1 then 'x' when a < 0 then 'y' else 'z' end from s3object",
            "select case a when 1 then 'one' end from s3object",
            "select coalesce(a, b, 'c'), nullif(a, b) from s3object where a not like 'x%' escape '!'",
            "select * from s3object where a not in (1, 2) and b not between 1 and 2 and c is not missing",
            "select `2007-02-23T12:14Z`, s.\"Name\", s.a[0].b, s['k'] from s3object s",
            "select count(*), sum(a), avg(a), min(a), max(a) from s3object",
            "select a || 'x' from s3object -- a comment",
        ] {
            parse(sql).unwrap_or_else(|e| panic!("{sql}: {e}"));
        }
    }

    #[test]
    fn errors_carry_aws_codes() {
        let code = |sql: &str| parse(sql).unwrap_err().code;
        assert_eq!(code("delete from s3object"), "ParseUnsupportedSelect");
        assert_eq!(code("select a"), "ParseSelectMissingFrom");
        assert_eq!(code("select * from t"), "InvalidDataSource");
        assert_eq!(
            code("select *, a from s3object"),
            "ParseAsteriskIsNotAloneInSelectList"
        );
        assert_eq!(code("select from s3object"), "ParseEmptySelect");
        assert_eq!(
            code("select nosuch(a) from s3object"),
            "UnsupportedFunction"
        );
        assert_eq!(
            code("select sum(*) from s3object"),
            "ParseUnsupportedCallWithStar"
        );
        assert_eq!(
            code("select cast(a as blob) from s3object"),
            "ParseExpectedTypeName"
        );
        assert_eq!(
            code("select extract(week from a) from s3object"),
            "ParseExpectedDatePart"
        );
        assert_eq!(code("select 'abc from s3object"), "LexerInvalidLiteral");
        assert_eq!(code("select a # b from s3object"), "LexerInvalidChar");
        assert_eq!(
            code("select a from s3object limit -1"),
            "EvaluatorNegativeLimit"
        );
        assert_eq!(
            code("select a from s3object where"),
            "ParseExpectedExpression"
        );
        assert_eq!(
            code("select case end from s3object"),
            "ParseUnexpectedKeyword"
        );
        assert_eq!(
            code("select a[*] from s3object"),
            "ParseInvalidContextForWildcardInSelectList"
        );
        // What RGW's tests send: a stray LIKE after the condition.
        let e = parse("select count(*) from stdin where _1 like \"%aeio%\" like;").unwrap_err();
        assert!(e.code.contains("UnsupportedSyntax"), "{e}");
    }

    #[test]
    fn double_quotes_are_names_until_bound() {
        let q = parse("select lower(\"AB12cd$$\") from s3object").unwrap();
        assert_eq!(
            items(&q)[0].expr,
            Expr::Call(
                Func::Lower,
                vec![Expr::Name(vec![Step::Key {
                    name: "AB12cd$$".into(),
                    exact: true
                }])]
            )
        );
        // No space needed after a quoted name.
        parse("select \"true\"from s3object").unwrap();
    }
}
