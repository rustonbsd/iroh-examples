use std::{collections::HashMap, net::{Ipv4Addr, SocketAddrV4}, str::FromStr, sync::Arc, thread::sleep, time::Duration};

use anyhow::bail;
use bytes::Bytes;
use ed25519_dalek::Signature;
use iroh::{discovery::{dns::DnsDiscovery, pkarr::{dht::DhtDiscovery, PkarrRelayClient}, ConcurrentDiscovery}, endpoint, Endpoint, NodeAddr, NodeId, PublicKey, RelayUrl, SecretKey};
use iroh_blobs::{net_protocol::Blobs, util::local_pool::{self, LocalPool}};
use iroh_docs::protocol::Docs;
use iroh_examples::protocols::{gossip_info::GossipTopic, gossip_topic_discovery::GossipBuilder, topic_tracker::{Topic, TopicTrackerProtocol}};
use iroh_gossip::{net::{Event, Gossip, GossipEvent, GossipReceiver, GossipSender}, proto::TopicId};
use serde::{Deserialize, Serialize};
use futures_lite::stream::StreamExt;


#[tokio::main]
async fn main() -> anyhow::Result<()> {


    for _ in 0..100000000 {
        
        let topic = Topic::from_passphrase("my test topic");
        let secret_key =  SecretKey::generate(rand::rngs::OsRng);
        
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
            println!("Topic-req: {:?}",topic_tracker.clone().topic_request(&topic).await);
        sleep(Duration::from_secs(1));
    }

    Ok(())
}