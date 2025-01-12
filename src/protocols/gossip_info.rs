use std::{collections::BTreeMap, fmt::Display, hash::Hash, str::FromStr};
extern crate sha2;

use anyhow::{anyhow, ensure, Result};
use bytes::Bytes;
use hickory_resolver::{proto::ProtoError, Name, TokioResolver};
use iroh::{NodeId, SecretKey};
use serde::{Deserialize, Serialize};

use sha2::{Digest, Sha256, Sha512};

/// The DNS name for the iroh TXT record.
pub const GOSSIP_TXT_NAME: &str = "iroh-gossip";

/// The attributes supported by iroh for [`IROH_TXT_NAME`] DNS resource records.
///
/// The resource record uses the lower-case names.
#[derive(
    Debug, strum::Display, strum::AsRefStr, strum::EnumString, Hash, Eq, PartialEq, Ord, PartialOrd,
)]
#[strum(serialize_all = "kebab-case")]
pub enum GossipAttr {
    /// URL of home relay.
    Topic,
}

/// Encodes a [`NodeId`] in [`z-base-32`] encoding.
///
/// [z-base-32]: https://philzimmermann.com/docs/human-oriented-base-32-encoding.txt
pub fn to_z32(node_id: &NodeId) -> String {
    z32::encode(node_id.as_bytes())
}

/// Parses a [`NodeId`] from [`z-base-32`] encoding.
///
/// [z-base-32]: https://philzimmermann.com/docs/human-oriented-base-32-encoding.txt
pub fn from_z32(s: &str) -> Result<NodeId> {
    let bytes = z32::decode(s.as_bytes()).map_err(|_| anyhow!("invalid z32"))?;
    let bytes: &[u8; 32] = &bytes.try_into().map_err(|_| anyhow!("not 32 bytes long"))?;
    let node_id = NodeId::from_bytes(bytes)?;
    Ok(node_id)
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

/// Information about the iroh node contained in an [`IROH_TXT_NAME`] TXT resource record.
#[derive(derive_more::Debug, Clone, Eq, PartialEq)]
pub struct GossipInfo {
    /// The [`NodeId`].
    pub node_id: NodeId,
    /// The advertised home relay server.
    pub topic: GossipTopic,
}

impl From<TxtAttrs<GossipAttr>> for GossipInfo {
    fn from(attrs: TxtAttrs<GossipAttr>) -> Self {
        (&attrs).into()
    }
}

impl From<&TxtAttrs<GossipAttr>> for GossipInfo {
    fn from(attrs: &TxtAttrs<GossipAttr>) -> Self {
        let node_id = attrs.node_id();
        let attrs = attrs.attrs();
        let topic = attrs
            .get(&GossipAttr::Topic)
            .into_iter()
            .flatten()
            .next()
            .map_or("", |v| v);

        let mut topic_bytes = [0u8; 32];
        topic_bytes.copy_from_slice(hex::decode(topic).unwrap_or("".into()).as_slice());

        Self {
            node_id: node_id,
            topic: GossipTopic(topic_bytes),
        }
    }
}

impl From<&GossipInfo> for TxtAttrs<GossipAttr> {
    fn from(info: &GossipInfo) -> Self {
        let mut attrs = vec![];
        attrs.push((GossipAttr::Topic, info.topic.to_string()));
        Self::from_parts(info.node_id, attrs.into_iter())
    }
}

impl GossipInfo {
    /// Creates a new [`NodeInfo`] from its parts.
    pub fn new(node_id: NodeId, topic: GossipTopic) -> Self {
        Self { node_id, topic }
    }

    fn to_attrs(&self) -> TxtAttrs<GossipAttr> {
        self.into()
    }

    /// Parses a [`NodeInfo`] from a set of DNS records.
    pub fn from_hickory_records(records: &[hickory_resolver::proto::rr::Record]) -> Result<Self> {
        let attrs = TxtAttrs::from_hickory_records(records)?;
        Ok(attrs.into())
    }

    /// Parses a [`NodeInfo`] from a [`pkarr::SignedPacket`].
    pub fn from_pkarr_signed_packet(packet: &pkarr::SignedPacket) -> Result<Self> {
        let attrs = TxtAttrs::from_pkarr_signed_packet(packet)?;
        Ok(attrs.into())
    }

    /// Creates a [`pkarr::SignedPacket`].
    ///
    /// This constructs a DNS packet and signs it with a [`SecretKey`].
    pub fn to_pkarr_signed_packet(
        &self,
        secret_key: &SecretKey,
        ttl: u32,
    ) -> Result<pkarr::SignedPacket> {
        self.to_attrs().to_pkarr_signed_packet(secret_key, ttl)
    }
}

/// Parses a [`NodeId`] from iroh DNS name.
///
/// Takes a [`hickory_resolver::proto::rr::Name`] DNS name and expects the first label to be
/// [`IROH_TXT_NAME`] and the second label to be a z32 encoded [`NodeId`]. Ignores
/// subsequent labels.
pub(crate) fn node_id_from_hickory_name(
    name: &hickory_resolver::proto::rr::Name,
) -> Option<NodeId> {
    if name.num_labels() < 2 {
        return None;
    }
    let mut labels = name.iter();
    let label = std::str::from_utf8(labels.next().expect("num_labels checked")).ok()?;
    if label != GOSSIP_TXT_NAME {
        return None;
    }
    println!("hickory: {:?}", name);
    let label = std::str::from_utf8(labels.next().expect("num_labels checked")).ok()?;
    let node_id = from_z32(label).ok()?;
    Some(node_id)
}

/// Attributes parsed from [`IROH_TXT_NAME`] TXT records.
///
/// This struct is generic over the key type. When using with [`String`], this will parse
/// all attributes. Can also be used with an enum, if it implements [`FromStr`] and
/// [`Display`].
#[derive(Debug)]
pub struct TxtAttrs<T> {
    node_id: NodeId,
    attrs: BTreeMap<T, Vec<String>>,
}

impl<T: FromStr + Display + Hash + Ord> TxtAttrs<T> {
    /// Creates [`TxtAttrs`] from a node id and an iterator of key-value pairs.
    pub fn from_parts(node_id: NodeId, pairs: impl Iterator<Item = (T, String)>) -> Self {
        let mut attrs: BTreeMap<T, Vec<String>> = BTreeMap::new();
        for (k, v) in pairs {
            attrs.entry(k).or_default().push(v);
        }
        Self { attrs, node_id }
    }

    pub fn topic(&self) -> Option<String> {
        for (k, v) in &self.attrs {
            println!("K: {k}; V: {v:?}");
            if k.to_string().to_lowercase() == "topic" {
                println!("TOPIC: {:?}", Some(v.first()?.to_string()));
                return Some(v.first()?.to_string());
            }
        }
        println!("TOPIC: NONE");
        None
    }

    /// Creates [`TxtAttrs`] from a node id and an iterator of "{key}={value}" strings.
    pub fn from_strings(node_id: NodeId, strings: impl Iterator<Item = String>) -> Result<Self> {
        let mut attrs: BTreeMap<T, Vec<String>> = BTreeMap::new();
        for s in strings {
            let mut parts = s.split('=');
            let (Some(key), Some(value)) = (parts.next(), parts.next()) else {
                continue;
            };
            let Ok(attr) = T::from_str(key) else {
                continue;
            };
            attrs.entry(attr).or_default().push(value.to_string());
        }
        Ok(Self { attrs, node_id })
    }

    async fn lookup(resolver: &TokioResolver, name: Name) -> Result<Self> {
        let name = ensure_iroh_txt_label(name)?;
        println!("name: {name}");
        let lookup = resolver.txt_lookup(name.clone()).await?;
        let attrs = Self::from_hickory_records(lookup.as_lookup().records())?;
        Ok(attrs)
    }

    /// Looks up attributes by [`NodeId`] and origin domain.
    pub async fn lookup_by_id(
        resolver: &TokioResolver,
        node_id: &NodeId,
        origin: &str,
    ) -> Result<Self> {
        let name = node_domain(node_id, origin)?;
        TxtAttrs::lookup(resolver, name).await
    }

    /// Looks up attributes by DNS name.
    pub async fn lookup_by_name(resolver: &TokioResolver, name: &str) -> Result<Self> {
        let name = Name::from_str(name)?;
        println!("NameLoopup: {name}");
        TxtAttrs::lookup(resolver, name).await
    }

    /// Returns the parsed attributes.
    pub fn attrs(&self) -> &BTreeMap<T, Vec<String>> {
        &self.attrs
    }

    /// Returns the node id.
    pub fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// Parses a set of DNS resource records.
    pub fn from_hickory_records(records: &[hickory_resolver::proto::rr::Record]) -> Result<Self> {
        use hickory_resolver::proto::rr;
        let mut records = records.iter().filter_map(|rr| match rr.data() {
            rr::RData::TXT(txt) => {
                node_id_from_hickory_name(rr.name()).map(|node_id| (node_id, txt))
            }
            _ => None,
        });
        let (node_id, first) = records.next().ok_or_else(|| {
            anyhow!("invalid DNS answer: no TXT record with name _iroh.z32encodedpubkey found")
        })?;
        ensure!(
            &records.all(|(n, _)| n == node_id),
            "invalid DNS answer: all _iroh txt records must belong to the same node domain"
        );
        let records = records.map(|(_, txt)| txt).chain(Some(first));
        let strings = records.map(ToString::to_string);
        Self::from_strings(node_id, strings)
    }

    /// Parses a [`pkarr::SignedPacket`].
    pub fn from_pkarr_signed_packet(packet: &pkarr::SignedPacket) -> Result<Self> {
        use pkarr::dns::{
            rdata::RData,
            {self},
        };
        let pubkey = packet.public_key();
        let pubkey_z32 = pubkey.to_z32();
        let node_id = NodeId::from(*pubkey.verifying_key());
        let zone = dns::Name::new(&pubkey_z32)?;
        let inner = packet.packet();
        let txt_data = inner.answers.iter().filter_map(|rr| match &rr.rdata {
            RData::TXT(txt) => match rr.name.without(&zone) {
                Some(name) if name.to_string() == GOSSIP_TXT_NAME => Some(txt),
                Some(_) | None => None,
            },
            _ => None,
        });

        let txt_strs = txt_data.filter_map(|s| String::try_from(s.clone()).ok());
        Self::from_strings(node_id, txt_strs)
    }

    fn to_txt_strings(&self) -> impl Iterator<Item = String> + '_ {
        self.attrs
            .iter()
            .flat_map(move |(k, vs)| vs.iter().map(move |v| format!("{k}={v}")))
    }

    /// Creates a [`pkarr::SignedPacket`]
    ///
    /// This constructs a DNS packet and signs it with a [`SecretKey`].
    pub fn to_pkarr_signed_packet(
        &self,
        secret_key: &SecretKey,
        ttl: u32,
    ) -> Result<pkarr::SignedPacket> {
        let packet = self.to_pkarr_dns_packet(ttl)?;
        let keypair = pkarr::Keypair::from_secret_key(&secret_key.to_bytes());
        let signed_packet = pkarr::SignedPacket::from_packet(&keypair, &packet)?;
        Ok(signed_packet)
    }

    fn to_pkarr_dns_packet(&self, ttl: u32) -> Result<pkarr::dns::Packet<'static>> {
        use pkarr::dns::{self, rdata};

        //let name = dns::Name::new(&format!("{}", GOSSIP_TXT_NAME))?.into_owned();
        let name = dns::Name::new(&"iroh-gossip.zmqc7qoiq9p5jzib3id8ejesste19yoqhkpn14m3b1w77c66o3zo").unwrap();
        println!("NAME REQ: {}", name);

        let mut packet = dns::Packet::new_reply(0);
        packet.questions.push(dns::Question::new(
            name.clone(),
            dns::QTYPE::ANY,
            dns::QCLASS::ANY,
            false,
        ));
        for s in self.to_txt_strings() {
            let mut txt = rdata::TXT::new();
            txt.add_string(&s)?;
            let rdata = rdata::RData::TXT(txt.into_owned());
            packet.answers.push(dns::ResourceRecord::new(
                name.clone(),
                dns::CLASS::IN,
                ttl,
                rdata,
            ));
            
        }
        println!("Packet: {packet:?}");
        Ok(packet)
    }
}

fn ensure_iroh_txt_label(name: Name) -> Result<Name, ProtoError> {
    if name.iter().next() == Some(GOSSIP_TXT_NAME.as_bytes()) {
        Ok(name)
    } else {
        Name::parse(GOSSIP_TXT_NAME, Some(&name))
    }
}

fn node_domain(node_id: &NodeId, origin: &str) -> Result<Name> {
    let domain = format!("{}.{}", to_z32(node_id), origin);
    println!("Domain {:?}", Name::from_str(&domain));
    let domain = Name::from_str(&domain)?;
    Ok(domain)
}

impl Into<SecretKey> for GossipTopic {
    fn into(self) -> SecretKey {
        SecretKey::from_bytes(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use iroh::NodeId;

    use super::GossipInfo;
    use super::GossipTopic;

    #[test]
    fn txt_attr_roundtrip() {
        let topic = GossipTopic::from_passphrase("test");
        let node_id = GossipTopic::from_passphrase("mynodeid");
        let expected = GossipInfo::new(node_id.to_secret_key().public(), topic);
        let attrs = expected.to_attrs();
        let actual = GossipInfo::from(&attrs);
        assert_eq!(expected, actual);
    }
}
