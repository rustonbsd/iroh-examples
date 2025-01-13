use std::{collections::HashMap, net::{Ipv4Addr, SocketAddrV4}, str::FromStr, sync::Arc, time::Duration};

use anyhow::bail;
use bytes::Bytes;
use ed25519_dalek::Signature;
use iroh::{discovery::{dns::DnsDiscovery, pkarr::{dht::DhtDiscovery, PkarrRelayClient}, ConcurrentDiscovery}, endpoint, Endpoint, NodeAddr, NodeId, PublicKey, RelayUrl, SecretKey};
use iroh_blobs::{net_protocol::Blobs, util::local_pool::{self, LocalPool}};
use iroh_docs::protocol::Docs;
use iroh_examples::{protocols::{gossip_info::GossipTopic, gossip_topic_discovery::GossipBuilder, topic_tracker::{Topic, TopicTrackerProtocol}}, secrets::SECRET_SERVER_KEY};
use iroh_gossip::{net::{Event, Gossip, GossipEvent, GossipReceiver, GossipSender}, proto::TopicId};
use rand::rngs;
use serde::{Deserialize, Serialize};
use futures_lite::stream::StreamExt;
use tokio::time::sleep;


#[tokio::main]
async fn main() -> anyhow::Result<()> {

    let topic = Topic::from_passphrase("my test topic");
    let secret_key =  SecretKey::from_str(SECRET_SERVER_KEY)?;
    
    let endpoint = Endpoint::builder()
        .secret_key(secret_key)
        .discovery_n0()
        .discovery_dht()
        .bind()
        .await?;
    
    let topic_tracker = Arc::new(TopicTrackerProtocol::new(&endpoint));
    let router = iroh::protocol::Router::builder(endpoint.clone())
        .accept(TopicTrackerProtocol::ALPN, topic_tracker.clone())
        .spawn()
        .await?;

    println!("Dedicated_node_id: {:?}",endpoint.node_id());

    sleep(Duration::from_secs(99999999999999)).await;

    Ok(())
}