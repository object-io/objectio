//! The OSD's metadata key-value store, as an interface (B27, objectio-docs
//! `core/osd-engines.md`): what the OSD needs of whichever engine keeps its
//! metadata, so one can replace another. [`MetadataStore`] (its own WAL,
//! memtable and redb index file) is the implementation today.
//!
//! The contract, which every implementation keeps and the conformance tests
//! check:
//!
//! - **Durable when acknowledged.** A [`MetaIndex::write`] that returns
//!   `Ok` is on stable storage: a power cut right after loses none of it.
//! - **Atomic.** A write's operations are applied all or none, after a
//!   crash too.
//! - **Read your writes.** A read after a write has returned sees what it
//!   wrote (until a later write changes it).
//! - **Bounded memory.** Nothing grows with the number of entries; a prefix
//!   of any size is read a page at a time.

use std::ops::Deref;
use std::sync::Arc;

use objectio_common::Result;

use super::store::MetadataStore;
use super::types::{MetadataKey, MetadataOp};

/// The OSD's metadata key-value store. See the module documentation for
/// what an implementation guarantees.
pub trait MetaIndex: Send + Sync {
    /// The value under `key`, if any.
    fn get(&self, key: &MetadataKey) -> Option<Vec<u8>>;

    /// Apply `ops` (puts and deletes, in order) atomically and durably. An
    /// empty `ops` is a no-op.
    ///
    /// # Errors
    /// The write could not be made durable; none of it is applied.
    fn write(&self, ops: Vec<MetadataOp>) -> Result<()>;

    /// Call `f` on each entry under `prefix`, in key order, from after
    /// `after` (or the start), until it returns false. Memory stays flat
    /// however many entries the prefix has. Not a snapshot: writes made
    /// meanwhile may or may not be seen.
    fn for_each_prefix(
        &self,
        prefix: &MetadataKey,
        after: Option<&MetadataKey>,
        f: &mut dyn FnMut(&[u8], &[u8]) -> bool,
    );

    /// How many entries it holds.
    fn len(&self) -> u64;

    /// Whether it holds none.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The engine's own Prometheus families, each series labelled with
    /// `labels` (e.g. `osd_id="…"`).
    fn render_metrics(&self, out: &mut String, labels: &str);

    /// Put one entry ([`Self::write`]).
    ///
    /// # Errors
    /// As [`Self::write`].
    fn put(&self, key: MetadataKey, value: Vec<u8>) -> Result<()> {
        self.write(vec![MetadataOp::Put { key, value }])
    }

    /// Delete one entry ([`Self::write`]).
    ///
    /// # Errors
    /// As [`Self::write`].
    fn delete(&self, key: &MetadataKey) -> Result<()> {
        self.write(vec![MetadataOp::Delete { key: key.clone() }])
    }

    /// Put many entries in one atomic write.
    ///
    /// # Errors
    /// As [`Self::write`].
    fn batch_put(&self, entries: Vec<(MetadataKey, Vec<u8>)>) -> Result<()> {
        self.write(
            entries
                .into_iter()
                .map(|(key, value)| MetadataOp::Put { key, value })
                .collect(),
        )
    }

    /// Delete many entries in one atomic write.
    ///
    /// # Errors
    /// As [`Self::write`].
    fn batch_delete(&self, keys: &[MetadataKey]) -> Result<()> {
        self.write(
            keys.iter()
                .map(|key| MetadataOp::Delete { key: key.clone() })
                .collect(),
        )
    }

    /// Every entry under `prefix`, collected: for prefixes known to be
    /// small (one key's versions). Larger ones go through
    /// [`Self::for_each_prefix`] or [`iter_prefix`].
    fn scan_prefix(&self, prefix: &MetadataKey) -> Vec<(MetadataKey, Vec<u8>)> {
        let mut out = Vec::new();
        self.for_each_prefix(prefix, None, &mut |k, v| {
            out.push((MetadataKey::from_bytes(k.to_vec()), v.to_vec()));
            true
        });
        out
    }
}

/// The entries under `prefix` in key order, from after `after`, read a page
/// at a time: for prefixes of any size. `store` is any handle on an index
/// (`&dyn MetaIndex`, `Arc<dyn MetaIndex>`), so the iterator may own it and
/// outlive the call that made it.
pub fn iter_prefix<S>(store: S, prefix: MetadataKey, after: Option<MetadataKey>) -> PrefixIter<S>
where
    S: Deref,
    S::Target: MetaIndex,
{
    PrefixIter {
        store,
        prefix,
        after,
        page: Vec::new().into_iter(),
        done: false,
    }
}

impl dyn MetaIndex {
    /// [`iter_prefix`] over this index from the start of `prefix`.
    pub fn iter_prefix(&self, prefix: &MetadataKey) -> PrefixIter<&Self> {
        iter_prefix(self, prefix.clone(), None)
    }

    /// [`iter_prefix`] over this index from after `after`.
    pub fn iter_prefix_after(
        &self,
        prefix: &MetadataKey,
        after: Option<MetadataKey>,
    ) -> PrefixIter<&Self> {
        iter_prefix(self, prefix.clone(), after)
    }
}

/// [`iter_prefix`]'s iterator.
pub struct PrefixIter<S> {
    store: S,
    prefix: MetadataKey,
    after: Option<MetadataKey>,
    page: std::vec::IntoIter<(MetadataKey, Vec<u8>)>,
    done: bool,
}

impl<S> PrefixIter<S> {
    const PAGE: usize = 1024;
}

impl<S> Iterator for PrefixIter<S>
where
    S: Deref,
    S::Target: MetaIndex,
{
    type Item = (MetadataKey, Vec<u8>);

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(e) = self.page.next() {
            return Some(e);
        }
        if self.done {
            return None;
        }
        let mut page = Vec::with_capacity(Self::PAGE);
        self.store
            .for_each_prefix(&self.prefix, self.after.as_ref(), &mut |k, v| {
                page.push((MetadataKey::from_bytes(k.to_vec()), v.to_vec()));
                page.len() < Self::PAGE
            });
        self.done = page.len() < Self::PAGE;
        self.after = page.last().map(|(k, _)| k.clone());
        self.page = page.into_iter();
        self.page.next()
    }
}

impl MetaIndex for MetadataStore {
    fn get(&self, key: &MetadataKey) -> Option<Vec<u8>> {
        Self::get(self, key)
    }

    fn write(&self, ops: Vec<MetadataOp>) -> Result<()> {
        Self::write(self, ops).map(|_| ())
    }

    fn for_each_prefix(
        &self,
        prefix: &MetadataKey,
        after: Option<&MetadataKey>,
        f: &mut dyn FnMut(&[u8], &[u8]) -> bool,
    ) {
        Self::for_each_prefix(self, prefix, after, f);
    }

    fn len(&self) -> u64 {
        Self::len(self)
    }

    fn render_metrics(&self, out: &mut String, labels: &str) {
        Self::render_metrics(self, out, labels);
    }
}

/// Open the OSD's metadata index at `config`: today the only engine.
///
/// # Errors
/// The store could not be opened or created.
pub fn open(config: super::store::MetadataStoreConfig) -> Result<Arc<dyn MetaIndex>> {
    Ok(Arc::new(MetadataStore::open_or_create(config)?))
}

/// The contract as tests, for any implementation: each takes a function
/// that opens the implementation's index in a directory (and opens it
/// again there, to check what survives).
#[cfg(test)]
pub(crate) mod conformance {
    use super::{MetaIndex, iter_prefix};
    use crate::metadata::{MetadataKey, MetadataOp};
    use std::path::Path;
    use std::sync::Arc;

    pub type Open = fn(&Path) -> Arc<dyn MetaIndex>;

    fn key(s: &str) -> MetadataKey {
        MetadataKey::from_bytes(s.as_bytes().to_vec())
    }

    /// Every check, against one implementation.
    pub fn run(open: Open) {
        reads_its_writes(open);
        a_write_is_all_or_nothing_in_order(open);
        prefixes_page_in_order_from_a_cursor(open);
        writes_survive_a_reopen(open);
    }

    fn reads_its_writes(open: Open) {
        let dir = tempfile::tempdir().unwrap();
        let ix = open(dir.path());
        assert!(ix.is_empty());
        assert_eq!(ix.get(&key("a")), None);
        ix.put(key("a"), b"1".to_vec()).unwrap();
        assert_eq!(ix.get(&key("a")).as_deref(), Some(&b"1"[..]));
        ix.put(key("a"), b"2".to_vec()).unwrap();
        assert_eq!(ix.get(&key("a")).as_deref(), Some(&b"2"[..]));
        assert_eq!(ix.len(), 1);
        ix.delete(&key("a")).unwrap();
        assert_eq!(ix.get(&key("a")), None);
        ix.write(Vec::new()).unwrap();
        assert!(ix.is_empty());
    }

    fn a_write_is_all_or_nothing_in_order(open: Open) {
        let dir = tempfile::tempdir().unwrap();
        let ix = open(dir.path());
        ix.put(key("gone"), b"x".to_vec()).unwrap();
        // Later operations in one write see earlier ones: a put then a
        // delete of the same key leaves nothing.
        ix.write(vec![
            MetadataOp::Put {
                key: key("k1"),
                value: b"v1".to_vec(),
            },
            MetadataOp::Delete { key: key("gone") },
            MetadataOp::Put {
                key: key("k2"),
                value: b"v2".to_vec(),
            },
            MetadataOp::Delete { key: key("k2") },
            MetadataOp::Put {
                key: key("k3"),
                value: b"v3".to_vec(),
            },
        ])
        .unwrap();
        assert_eq!(ix.get(&key("k1")).as_deref(), Some(&b"v1"[..]));
        assert_eq!(ix.get(&key("gone")), None);
        assert_eq!(ix.get(&key("k2")), None);
        assert_eq!(ix.get(&key("k3")).as_deref(), Some(&b"v3"[..]));
        assert_eq!(ix.len(), 2);
    }

    fn prefixes_page_in_order_from_a_cursor(open: Open) {
        let dir = tempfile::tempdir().unwrap();
        let ix = open(dir.path());
        // More than one page (1024), with neighbours on both sides.
        let n = 2500;
        ix.batch_put(
            (0..n)
                .map(|i| (key(&format!("p/{i:05}")), i.to_string().into_bytes()))
                .chain([(key("o/x"), vec![]), (key("q/x"), vec![])])
                .collect(),
        )
        .unwrap();
        let all: Vec<_> = iter_prefix(&*ix, key("p/"), None).collect();
        assert_eq!(all.len(), n);
        assert!(
            all.windows(2).all(|w| w[0].0.0 < w[1].0.0),
            "not in key order"
        );
        let from = iter_prefix(&*ix, key("p/"), Some(key("p/01999")))
            .next()
            .unwrap();
        assert_eq!(from.0, key("p/02000"));
        let mut seen = 0;
        ix.for_each_prefix(&key("p/"), None, &mut |_, _| {
            seen += 1;
            seen < 10
        });
        assert_eq!(seen, 10, "for_each_prefix kept going after false");
        assert_eq!(ix.scan_prefix(&key("q/")).len(), 1);
    }

    fn writes_survive_a_reopen(open: Open) {
        let dir = tempfile::tempdir().unwrap();
        {
            let ix = open(dir.path());
            ix.put(key("a"), b"1".to_vec()).unwrap();
            ix.write(vec![
                MetadataOp::Put {
                    key: key("b"),
                    value: b"2".to_vec(),
                },
                MetadataOp::Delete { key: key("a") },
            ])
            .unwrap();
        }
        let ix = open(dir.path());
        assert_eq!(ix.get(&key("a")), None);
        assert_eq!(ix.get(&key("b")).as_deref(), Some(&b"2"[..]));
        assert_eq!(ix.len(), 1);
    }
}

#[cfg(test)]
mod tests {
    use super::conformance;
    use crate::metadata::MetadataStoreConfig;

    #[test]
    fn metadata_store_keeps_the_contract() {
        conformance::run(|dir| super::open(MetadataStoreConfig::with_data_dir(dir)).unwrap());
    }
}
