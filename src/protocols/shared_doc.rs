extern crate sha2;

use std::str::FromStr;

use anyhow::{bail, ensure, Context, Result};
use bytes::Bytes;
use futures_lite::{Stream, StreamExt};
use iroh::SecretKey;
use iroh_docs::rpc::client::docs::Doc;
use iroh_docs::rpc::client::docs::{Entry, LiveEvent, ShareMode};
use iroh_docs::{store::Query, AuthorId, DocTicket};

use quic_rpc::transport::flume::FlumeConnector;
// use iroh::ticket::DocTicket;
use serde::{Deserialize, Serialize};

use sha2::{Digest, Sha256, Sha512};
use crate::iroh::Iroh;


pub struct GossipTable {
    iroh: Iroh,
    doc: Doc<FlumeConnector<iroh_docs::rpc::proto::Response, iroh_docs::rpc::proto::Request>>,

    ticket: DocTicket,
    author: AuthorId,
}
const MAX_TABLE_ENTRY_SIZE: usize = 2 * 1024;
const NODE_ID_LEN: usize = 52;
impl GossipTable {
    pub async fn new(ticket: Option<String>, iroh: Iroh) -> anyhow::Result<Self> {
        let author = iroh.docs.authors().create().await?;

        let doc = match ticket {
            None => iroh.docs.create().await?,
            Some(ticket) => {
                let ticket = DocTicket::from_str(&ticket)?;
                iroh.docs.import(ticket).await?
            }
        };

        let ticket = doc.share(ShareMode::Write, Default::default()).await?;

        Ok(GossipTable {
            iroh,
            author,
            doc,
            ticket,
        })
    }

    pub fn ticket(&self) -> String {
        self.ticket.to_string()
    }

    pub async fn doc_subscribe(&self) -> Result<impl Stream<Item = Result<LiveEvent>>> {
        self.doc.subscribe().await
    }

    pub async fn add(&mut self, id: String, node_id: String, topic_id: String) -> anyhow::Result<()> {
        println!("node id: {node_id} {}",node_id.len());
        if node_id.len() > NODE_ID_LEN {
            bail!("NODE_ID is too long, max size is {NODE_ID_LEN} BYTES");
        }
        let created = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .expect("time drift")
            .as_secs();
        let table_entry = GossipTableEntry {
            node_id: node_id,
            created,
            topic_id: topic_id,
            is_active: true,
            id: id.clone(),
        };
        self.insert_bytes(id.as_bytes(), table_entry.as_bytes()?).await
    }

    pub async fn deactivate(&mut self, id: String) -> anyhow::Result<()> {
        let mut table_entry = self.get_table_entry(id.clone()).await?;
        table_entry.is_active = false;
        self.update_table_entry(id.as_bytes(), table_entry).await
    }

    pub async fn update(&mut self, id: String, node_id: String) -> anyhow::Result<()> {
        if node_id.len() >= NODE_ID_LEN {
            bail!("label is too long, must be {NODE_ID_LEN} or shorter");
        }
        let mut table_entry = self.get_table_entry(id.clone()).await?;
        table_entry.node_id = node_id;
        self.update_table_entry(id.as_bytes(), table_entry).await
    }

    pub async fn get_table_entries(&self) -> anyhow::Result<Vec<GossipTableEntry>> {
        let mut entries = self.doc.get_many(Query::single_latest_per_key()).await?;

        let mut table_entries = Vec::new();
        while let Some(entry) = entries.next().await {
            let entry = entry?;
            let table_entry = self.table_entry_from_entry(&entry).await?;
            if !table_entry.is_active {
                table_entries.push(table_entry);
            }
        }
        table_entries.sort_by_key(|t| t.created);
        Ok(table_entries)
    }

    async fn insert_bytes(&self, key: impl AsRef<[u8]>, content: Bytes) -> anyhow::Result<()> {
        self.doc
            .set_bytes(self.author, key.as_ref().to_vec(), content)
            .await?;
        Ok(())
    }

    async fn update_table_entry(&mut self, key: impl AsRef<[u8]>, table_entry: GossipTableEntry) -> anyhow::Result<()> {
        let content = table_entry.as_bytes()?;
        self.insert_bytes(key, content).await
    }

    async fn get_table_entry(&self, id: String) -> anyhow::Result<GossipTableEntry> {
        let entry = self
            .doc
            .get_many(Query::single_latest_per_key().key_exact(id))
            .await?
            .next()
            .await
            .ok_or_else(|| anyhow::anyhow!("no table entry found"))??;

        self.table_entry_from_entry(&entry).await
    }

    async fn table_entry_from_entry(&self, entry: &Entry) -> anyhow::Result<GossipTableEntry> {
        let id = String::from_utf8(entry.key().to_owned()).context("invalid key")?;
        match self.iroh.blobs.read_to_bytes(entry.content_hash()).await {
            Ok(b) => GossipTableEntry::from_bytes(b),
            Err(_) => Ok(GossipTableEntry::missing_table_entry(id)),
        }
    }
}



#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GossipTableEntry {
    /// String id
    pub id: String,
    pub node_id: String,
    pub topic_id: String,
    pub is_active: bool,
    pub created: u64,
}

impl GossipTableEntry {
    fn from_bytes(bytes: Bytes) -> anyhow::Result<Self> {
        let table_entry = serde_json::from_slice(&bytes).context("invalid json")?;
        Ok(table_entry)
    }

    fn as_bytes(&self) -> anyhow::Result<Bytes> {
        let buf = serde_json::to_vec(self)?;
        ensure!(buf.len() < MAX_TABLE_ENTRY_SIZE, "table entry too large");
        Ok(buf.into())
    }

    fn missing_table_entry(id: String) -> Self {
        Self {
            node_id: String::from("Missing node id"),
            topic_id: String::from("Missing topic id"),
            created: 0,
            is_active: false,
            id: id,
        }
    }
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GossipTopic([u8; 32]);

impl GossipTopic {
    pub fn new(topic: [u8; 32]) -> Self {
        Self(topic)
    }

    pub fn from_passphrase(phrase: &str) -> Self {
        Self(Self::hash(phrase))
    }

    fn hash(s: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(s.clone());
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&hasher.finalize()[..32]);
        buf
    }

    pub fn to_string(&self) -> String {
        hex::encode(self.0.clone())
    }

    pub fn to_secret_key(&self) -> SecretKey {
        SecretKey::from_bytes(&self.0.clone())
    }
}

impl Default for GossipTopic {
    fn default() -> Self {
        Self::from_passphrase("123")
    }
}