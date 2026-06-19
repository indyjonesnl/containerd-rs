//! Persistent metadata store backed by redb.
//!
//! Analogous to containerd's single-file bbolt `meta.db`: a transactional store
//! holding image / container / sandbox / snapshot-ref / lease records, with all
//! keys partitioned by runtime namespace. Records are serialized as JSON; the
//! reference graph is intentionally simpler than containerd's tri-color GC
//! (see `records` for the typed record shapes).

pub mod records;

use redb::{Database, ReadableTable, TableDefinition};
use serde::{de::DeserializeOwned, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    // redb error types are large (~160 bytes); box them through redb::Error so
    // this enum stays small (clippy::result_large_err).
    #[error("redb error: {0}")]
    Db(Box<redb::Error>),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

macro_rules! from_redb {
    ($($t:ty),+ $(,)?) => {
        $(impl From<$t> for Error {
            fn from(e: $t) -> Self {
                Error::Db(Box::new(e.into()))
            }
        })+
    };
}

from_redb!(
    redb::Error,
    redb::TransactionError,
    redb::TableError,
    redb::StorageError,
    redb::CommitError,
    redb::DatabaseError,
);

type Result<T> = std::result::Result<T, Error>;

// One table per record kind. Keys are "<namespace>/<id>".
const IMAGES: TableDefinition<&str, &[u8]> = TableDefinition::new("images");
const CONTAINERS: TableDefinition<&str, &[u8]> = TableDefinition::new("containers");
const SANDBOXES: TableDefinition<&str, &[u8]> = TableDefinition::new("sandboxes");
const SNAPSHOTS: TableDefinition<&str, &[u8]> = TableDefinition::new("snapshot_refs");
const LEASES: TableDefinition<&str, &[u8]> = TableDefinition::new("leases");

/// The kind of record, selecting which table it lives in.
#[derive(Debug, Clone, Copy)]
pub enum Kind {
    Image,
    Container,
    Sandbox,
    SnapshotRef,
    Lease,
}

impl Kind {
    fn table(self) -> TableDefinition<'static, &'static str, &'static [u8]> {
        match self {
            Kind::Image => IMAGES,
            Kind::Container => CONTAINERS,
            Kind::Sandbox => SANDBOXES,
            Kind::SnapshotRef => SNAPSHOTS,
            Kind::Lease => LEASES,
        }
    }
}

/// Transactional metadata store.
pub struct Store {
    db: Database,
}

fn key(namespace: &str, id: &str) -> String {
    format!("{namespace}/{id}")
}

impl Store {
    /// Open (creating if needed) the metadata database at `path`.
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let db = Database::create(path)?;
        // Ensure all tables exist so reads on a fresh db don't fail.
        let wtxn = db.begin_write()?;
        {
            wtxn.open_table(IMAGES)?;
            wtxn.open_table(CONTAINERS)?;
            wtxn.open_table(SANDBOXES)?;
            wtxn.open_table(SNAPSHOTS)?;
            wtxn.open_table(LEASES)?;
        }
        wtxn.commit()?;
        Ok(Self { db })
    }

    /// Insert or replace a record.
    pub fn put<T: Serialize>(
        &self,
        kind: Kind,
        namespace: &str,
        id: &str,
        value: &T,
    ) -> Result<()> {
        let bytes = serde_json::to_vec(value)?;
        let k = key(namespace, id);
        let wtxn = self.db.begin_write()?;
        {
            let mut table = wtxn.open_table(kind.table())?;
            table.insert(k.as_str(), bytes.as_slice())?;
        }
        wtxn.commit()?;
        Ok(())
    }

    /// Fetch a record by id within a namespace.
    pub fn get<T: DeserializeOwned>(
        &self,
        kind: Kind,
        namespace: &str,
        id: &str,
    ) -> Result<Option<T>> {
        let k = key(namespace, id);
        let rtxn = self.db.begin_read()?;
        let table = rtxn.open_table(kind.table())?;
        match table.get(k.as_str())? {
            Some(guard) => Ok(Some(serde_json::from_slice(guard.value())?)),
            None => Ok(None),
        }
    }

    /// Delete a record; returns whether it existed.
    pub fn delete(&self, kind: Kind, namespace: &str, id: &str) -> Result<bool> {
        let k = key(namespace, id);
        let wtxn = self.db.begin_write()?;
        let existed;
        {
            let mut table = wtxn.open_table(kind.table())?;
            existed = table.remove(k.as_str())?.is_some();
        }
        wtxn.commit()?;
        Ok(existed)
    }

    /// List all records of a kind within a namespace.
    pub fn list<T: DeserializeOwned>(&self, kind: Kind, namespace: &str) -> Result<Vec<T>> {
        let prefix = format!("{namespace}/");
        let rtxn = self.db.begin_read()?;
        let table = rtxn.open_table(kind.table())?;
        let mut out = Vec::new();
        for item in table.iter()? {
            let (k, v) = item?;
            if k.value().starts_with(&prefix) {
                out.push(serde_json::from_slice(v.value())?);
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct Rec {
        id: String,
        val: u32,
    }

    #[test]
    fn put_get_list_delete_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("meta.db")).unwrap();

        let r = Rec {
            id: "a".into(),
            val: 7,
        };
        store.put(Kind::Image, "k8s.io", "a", &r).unwrap();

        let got: Option<Rec> = store.get(Kind::Image, "k8s.io", "a").unwrap();
        assert_eq!(
            got,
            Some(Rec {
                id: "a".into(),
                val: 7
            })
        );

        // Namespace isolation: same id in another namespace is absent.
        let other: Option<Rec> = store.get(Kind::Image, "default", "a").unwrap();
        assert!(other.is_none());

        store
            .put(
                Kind::Image,
                "k8s.io",
                "b",
                &Rec {
                    id: "b".into(),
                    val: 9,
                },
            )
            .unwrap();
        let mut listed: Vec<Rec> = store.list(Kind::Image, "k8s.io").unwrap();
        listed.sort_by_key(|r| r.val);
        assert_eq!(listed.len(), 2);

        assert!(store.delete(Kind::Image, "k8s.io", "a").unwrap());
        assert!(!store.delete(Kind::Image, "k8s.io", "a").unwrap());
    }
}
