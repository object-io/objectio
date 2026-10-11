//! Parquet records, through the `parquet` crate's record API.
//!
//! Parquet keeps its schema and row-group index at the end of the file and
//! each column in its own chunk, so it can't be read front to back. It is
//! read in ranges instead: the footer, then the chunks of the columns the
//! statement names (all of them for `SELECT *`), each a ranged read of the
//! object through 1 MiB blocks with a bounded cache. Memory is what one
//! row group's pages of those columns take, not the object's size.

use super::error::{SelectError, SelectResult, from_io, to_io};
use super::value::Value;
use bytes::{Bytes, BytesMut};
use parquet::errors::ParquetError;
use parquet::file::reader::{ChunkReader, FileReader, Length, SerializedFileReader};
use parquet::record::Field;
use parquet::schema::types::Type;
use std::collections::{HashMap, VecDeque};
use std::io::Read;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

const BLOCK: u64 = 1024 * 1024;
/// Blocks kept: enough for a page of each of many columns at once.
const CACHED_BLOCKS: usize = 64;

/// Reads `len` bytes at `start` of the object.
pub type Fetch = dyn Fn(u64, u64) -> SelectResult<Bytes> + Send + Sync;

struct Inner {
    len: u64,
    fetch: Box<Fetch>,
    cache: parking_lot::Mutex<(HashMap<u64, Bytes>, VecDeque<u64>)>,
}

/// A Parquet object read in ranges.
#[derive(Clone)]
pub struct RemoteFile(Arc<Inner>);

impl RemoteFile {
    pub fn new(len: u64, fetch: Box<Fetch>) -> Self {
        Self(Arc::new(Inner {
            len,
            fetch,
            cache: parking_lot::Mutex::new((HashMap::new(), VecDeque::new())),
        }))
    }

    fn fetch(&self, start: u64, len: u64) -> SelectResult<Bytes> {
        let b = (self.0.fetch)(start, len)?;
        if (b.len() as u64) < len {
            return Err(SelectError::internal(
                "the object ended before its Parquet footer said",
            ));
        }
        Ok(b)
    }

    fn bytes(&self, start: u64, len: u64) -> SelectResult<Bytes> {
        if len == 0 {
            return Ok(Bytes::new());
        }
        if start.checked_add(len).is_none_or(|end| end > self.0.len) {
            return Err(SelectError::new(
                "ParquetParsingError",
                "the Parquet file refers past its end",
            ));
        }
        let first = start / BLOCK;
        let last = (start + len - 1) / BLOCK;
        // Too big to cache: read it as it is.
        if (last - first + 1) as usize > CACHED_BLOCKS / 2 {
            return self.fetch(start, len);
        }
        let missing: Vec<u64> = {
            let cache = self.0.cache.lock();
            (first..=last)
                .filter(|b| !cache.0.contains_key(b))
                .collect()
        };
        // One read per run of missing blocks.
        let mut i = 0;
        while i < missing.len() {
            let mut j = i;
            while j + 1 < missing.len() && missing[j + 1] == missing[j] + 1 {
                j += 1;
            }
            let from = missing[i] * BLOCK;
            let to = ((missing[j] + 1) * BLOCK).min(self.0.len);
            let data = self.fetch(from, to - from)?;
            let mut cache = self.0.cache.lock();
            for (k, b) in (missing[i]..=missing[j]).enumerate() {
                let lo = k as u64 * BLOCK;
                let hi = (lo + BLOCK).min(data.len() as u64);
                cache.0.insert(b, data.slice(lo as usize..hi as usize));
                cache.1.push_back(b);
            }
            while cache.1.len() > CACHED_BLOCKS {
                if let Some(old) = cache.1.pop_front() {
                    cache.0.remove(&old);
                }
            }
            i = j + 1;
        }
        let cache = self.0.cache.lock();
        let block = |b: u64| -> SelectResult<Bytes> {
            cache
                .0
                .get(&b)
                .cloned()
                .ok_or_else(|| SelectError::internal("a Parquet block left the cache too soon"))
        };
        if first == last {
            let off = (start - first * BLOCK) as usize;
            return Ok(block(first)?.slice(off..off + len as usize));
        }
        let mut out = BytesMut::with_capacity(len as usize);
        for b in first..=last {
            let data = block(b)?;
            let lo = start.saturating_sub(b * BLOCK) as usize;
            let hi = ((start + len).saturating_sub(b * BLOCK) as usize).min(data.len());
            out.extend_from_slice(&data[lo..hi]);
        }
        Ok(out.freeze())
    }
}

fn to_parquet(e: SelectError) -> ParquetError {
    ParquetError::External(Box::new(e))
}

impl Length for RemoteFile {
    fn len(&self) -> u64 {
        self.0.len
    }
}

/// A reader from an offset, block by block.
pub struct RemoteRead {
    file: RemoteFile,
    pos: u64,
}

impl Read for RemoteRead {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let left = self.file.0.len.saturating_sub(self.pos);
        if left == 0 || buf.is_empty() {
            return Ok(0);
        }
        let to_block_end = BLOCK - self.pos % BLOCK;
        let n = (buf.len() as u64).min(left).min(to_block_end);
        let data = self.file.bytes(self.pos, n).map_err(to_io)?;
        buf[..data.len()].copy_from_slice(&data);
        self.pos += data.len() as u64;
        Ok(data.len())
    }
}

impl ChunkReader for RemoteFile {
    type T = RemoteRead;

    fn get_read(&self, start: u64) -> parquet::errors::Result<RemoteRead> {
        Ok(RemoteRead {
            file: self.clone(),
            pos: start,
        })
    }

    fn get_bytes(&self, start: u64, length: usize) -> parquet::errors::Result<Bytes> {
        self.bytes(start, length as u64).map_err(to_parquet)
    }
}

/// A Parquet error as S3 Select reports it.
pub fn from_parquet(e: ParquetError) -> SelectError {
    match e {
        ParquetError::External(inner) => match inner.downcast::<SelectError>() {
            Ok(s) => *s,
            Err(other) => match other.downcast::<std::io::Error>() {
                Ok(io) => from_io(*io, "ParquetParsingError"),
                Err(other) => SelectError::new("ParquetParsingError", other.to_string()),
            },
        },
        other => SelectError::new(
            "ParquetParsingError",
            format!("the object is not a Parquet file S3 Select can read: {other}"),
        ),
    }
}

/// An open Parquet object: its schema, then its rows.
pub struct ParquetInput {
    reader: SerializedFileReader<RemoteFile>,
}

impl ParquetInput {
    pub fn open(file: RemoteFile) -> SelectResult<Self> {
        let reader = SerializedFileReader::new(file).map_err(from_parquet)?;
        Ok(Self { reader })
    }

    /// The top-level columns.
    pub fn columns(&self) -> Vec<String> {
        self.root()
            .get_fields()
            .iter()
            .map(|f| f.name().to_string())
            .collect()
    }

    fn root(&self) -> &Type {
        self.reader
            .metadata()
            .file_metadata()
            .schema_descr()
            .root_schema()
    }

    /// Every row, as a struct of the `wanted` columns (by index; all when
    /// `None`), of the row groups that start in `range`, to `f` until it
    /// says stop. The uncompressed size of the column chunks read is added
    /// to `processed`.
    pub fn scan(
        &self,
        wanted: Option<&[usize]>,
        range: Option<(u64, u64)>,
        processed: &AtomicU64,
        f: &mut dyn FnMut(Value) -> SelectResult<bool>,
    ) -> SelectResult<()> {
        let root = self.root();
        let projection = match wanted {
            None => None,
            Some(cols) => {
                let fields = cols.iter().map(|&i| root.get_fields()[i].clone()).collect();
                Some(
                    Type::group_type_builder(root.name())
                        .with_fields(fields)
                        .build()
                        .map_err(from_parquet)?,
                )
            }
        };
        let meta = self.reader.metadata();
        for g in 0..self.reader.num_row_groups() {
            let rg = meta.row_group(g);
            let start = rg
                .columns()
                .iter()
                .map(|c| c.byte_range().0)
                .min()
                .unwrap_or(0);
            if let Some((lo, hi)) = range
                && (start < lo || start > hi)
            {
                continue;
            }
            let bytes = rg
                .columns()
                .iter()
                .enumerate()
                .filter(|(i, _)| {
                    wanted.is_none_or(|w| {
                        // A column chunk belongs to the top-level column its
                        // path starts with.
                        let top = rg.schema_descr().column(*i).path().parts()[0].clone();
                        w.iter().any(|&c| root.get_fields()[c].name() == top)
                    })
                })
                .map(|(_, c)| c.uncompressed_size().max(0) as u64)
                .sum::<u64>();
            processed.fetch_add(bytes, Ordering::Relaxed);
            let group = self.reader.get_row_group(g).map_err(from_parquet)?;
            let rows = group
                .get_row_iter(projection.clone())
                .map_err(from_parquet)?;
            for row in rows {
                let row = row.map_err(from_parquet)?;
                let rec = Value::Struct(
                    row.get_column_iter()
                        .map(|(k, v)| (k.clone(), field(v)))
                        .collect(),
                );
                if !f(rec)? {
                    return Ok(());
                }
            }
        }
        Ok(())
    }
}

/// A Parquet value as a SQL one.
fn field(f: &Field) -> Value {
    match f {
        Field::Null => Value::Null,
        Field::Bool(b) => Value::Bool(*b),
        Field::Byte(i) => Value::Int(i64::from(*i)),
        Field::Short(i) => Value::Int(i64::from(*i)),
        Field::Int(i) => Value::Int(i64::from(*i)),
        Field::Long(i) => Value::Int(*i),
        Field::UByte(i) => Value::Int(i64::from(*i)),
        Field::UShort(i) => Value::Int(i64::from(*i)),
        Field::UInt(i) => Value::Int(i64::from(*i)),
        Field::ULong(i) => i64::try_from(*i).map_or(Value::Float(*i as f64), Value::Int),
        Field::Float16(h) => Value::Float(f64::from(h.to_f32())),
        Field::Float(x) => Value::Float(f64::from(*x)),
        Field::Double(x) => Value::Float(*x),
        Field::Decimal(d) => Value::Float(decimal(d.data(), d.scale())),
        Field::Str(s) => Value::Str(s.clone()),
        Field::Bytes(b) => Value::Str(String::from_utf8_lossy(b.data()).into_owned()),
        Field::Date(days) => super::datetime::from_epoch(
            i64::from(*days) * 86_400,
            0,
            super::datetime::Precision::Day,
        )
        .map_or(Value::Null, Value::Timestamp),
        Field::TimeMillis(ms) => Value::Int(i64::from(*ms)),
        Field::TimeMicros(us) => Value::Int(*us),
        Field::TimestampMillis(ms) => super::datetime::from_epoch(
            ms.div_euclid(1000),
            (ms.rem_euclid(1000) * 1_000_000) as u32,
            super::datetime::Precision::Fraction(3),
        )
        .map_or(Value::Null, Value::Timestamp),
        Field::TimestampMicros(us) => super::datetime::from_epoch(
            us.div_euclid(1_000_000),
            (us.rem_euclid(1_000_000) * 1000) as u32,
            super::datetime::Precision::Fraction(6),
        )
        .map_or(Value::Null, Value::Timestamp),
        Field::Group(row) => Value::Struct(
            row.get_column_iter()
                .map(|(k, v)| (k.clone(), field(v)))
                .collect(),
        ),
        Field::ListInternal(list) => Value::List(list.elements().iter().map(field).collect()),
        Field::MapInternal(map) => Value::Struct(
            map.entries()
                .iter()
                .map(|(k, v)| (field(k).to_text(), field(v)))
                .collect(),
        ),
    }
}

/// A big-endian two's-complement unscaled decimal.
fn decimal(be: &[u8], scale: i32) -> f64 {
    let mut v: i128 = if be.first().is_some_and(|b| b & 0x80 != 0) {
        -1
    } else {
        0
    };
    for &b in be.iter().take(16) {
        v = (v << 8) | i128::from(b);
    }
    v as f64 / 10f64.powi(scale)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use parquet::data_type::{ByteArray, ByteArrayType, DoubleType, Int64Type};
    use parquet::file::properties::WriterProperties;
    use parquet::file::writer::SerializedFileWriter;
    use parquet::schema::parser::parse_message_type;

    /// A Parquet file of `rows` rows: `id` (int64), `name` (string),
    /// `score` (double, null on every third row), in row groups of `group`.
    pub(crate) fn sample(rows: i64, group: i64) -> Vec<u8> {
        let schema = Arc::new(
            parse_message_type(
                "message schema { REQUIRED INT64 id; REQUIRED BYTE_ARRAY name (UTF8); OPTIONAL DOUBLE score; }",
            )
            .unwrap(),
        );
        let props = Arc::new(WriterProperties::builder().build());
        let mut out = Vec::new();
        let mut w = SerializedFileWriter::new(&mut out, schema, props).unwrap();
        let mut start = 0;
        while start < rows {
            let end = (start + group).min(rows);
            let ids: Vec<i64> = (start..end).collect();
            let names: Vec<ByteArray> = ids
                .iter()
                .map(|i| ByteArray::from(format!("n{i}").as_str()))
                .collect();
            let scores: Vec<f64> = ids
                .iter()
                .filter(|i| *i % 3 != 0)
                .map(|i| *i as f64 / 2.0)
                .collect();
            let defs: Vec<i16> = ids.iter().map(|i| i16::from(*i % 3 != 0)).collect();
            let mut rg = w.next_row_group().unwrap();
            let mut c = rg.next_column().unwrap().unwrap();
            c.typed::<Int64Type>()
                .write_batch(&ids, None, None)
                .unwrap();
            c.close().unwrap();
            let mut c = rg.next_column().unwrap().unwrap();
            c.typed::<ByteArrayType>()
                .write_batch(&names, None, None)
                .unwrap();
            c.close().unwrap();
            let mut c = rg.next_column().unwrap().unwrap();
            c.typed::<DoubleType>()
                .write_batch(&scores, Some(&defs), None)
                .unwrap();
            c.close().unwrap();
            rg.close().unwrap();
            start = end;
        }
        w.close().unwrap();
        out
    }

    pub(crate) fn in_memory(data: Vec<u8>) -> RemoteFile {
        let data = Bytes::from(data);
        let len = data.len() as u64;
        RemoteFile::new(
            len,
            Box::new(move |start, n| {
                let end = (start + n).min(data.len() as u64);
                Ok(data.slice(start as usize..end as usize))
            }),
        )
    }

    #[test]
    fn rows_come_out_as_structs() {
        let input = ParquetInput::open(in_memory(sample(10, 4))).unwrap();
        assert_eq!(input.columns(), ["id", "name", "score"]);
        let mut rows = Vec::new();
        let processed = AtomicU64::new(0);
        input
            .scan(None, None, &processed, &mut |v| {
                rows.push(v);
                Ok(true)
            })
            .unwrap();
        assert_eq!(rows.len(), 10);
        assert_eq!(
            rows[1],
            Value::Struct(vec![
                ("id".into(), Value::Int(1)),
                ("name".into(), Value::Str("n1".into())),
                ("score".into(), Value::Float(0.5)),
            ])
        );
        assert_eq!(
            rows[3],
            Value::Struct(vec![
                ("id".into(), Value::Int(3)),
                ("name".into(), Value::Str("n3".into())),
                ("score".into(), Value::Null),
            ])
        );
        assert!(processed.load(Ordering::Relaxed) > 0);
    }

    #[test]
    fn a_projection_reads_its_columns_only() {
        let input = ParquetInput::open(in_memory(sample(10, 4))).unwrap();
        let mut rows = Vec::new();
        let processed = AtomicU64::new(0);
        input
            .scan(Some(&[1]), None, &processed, &mut |v| {
                rows.push(v);
                Ok(rows.len() < 3)
            })
            .unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(
            rows[2],
            Value::Struct(vec![("name".into(), Value::Str("n2".into()))])
        );
    }

    #[test]
    fn a_scan_range_picks_row_groups() {
        let data = sample(100, 10);
        let size = data.len() as u64;
        let input = ParquetInput::open(in_memory(data)).unwrap();
        let mut n = 0;
        let processed = AtomicU64::new(0);
        input
            .scan(None, Some((0, 4)), &processed, &mut |_| {
                n += 1;
                Ok(true)
            })
            .unwrap();
        assert_eq!(n, 10, "only the first row group starts in the first bytes");
        let mut all = 0;
        input
            .scan(None, Some((0, size - 1)), &processed, &mut |_| {
                all += 1;
                Ok(true)
            })
            .unwrap();
        assert_eq!(all, 100);
    }

    #[test]
    fn not_parquet_is_an_error() {
        let e = ParquetInput::open(in_memory(b"name,id\nx,1\n".to_vec()))
            .err()
            .unwrap();
        assert_eq!(e.code, "ParquetParsingError");
    }

    #[test]
    fn decimals_scale() {
        assert_eq!(decimal(&[0x04, 0xd2], 2), 12.34);
        assert_eq!(decimal(&[0xff, 0x85], 1), -12.3);
    }
}
