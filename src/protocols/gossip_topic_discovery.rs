use std::{fmt::Debug, time::Duration};

use iroh::{
    discovery::{
        dns::N0_DNS_NODE_ORIGIN_PROD,
        pkarr::{PkarrRelayClient, N0_DNS_PKARR_RELAY_PROD},
    },
    dns::node_info::{NodeInfo, IROH_TXT_NAME},
    Endpoint, NodeId, SecretKey,
};
use serde::{Deserialize, Serialize};
use tokio::time::sleep;

use crate::protocols::gossip_info::GOSSIP_TXT_NAME;

use super::gossip_info::{GossipInfo, GossipTopic, TxtAttrs};

#[derive(Debug, Clone)]
pub struct Gossip {
    topic: GossipTopic,
    endpoint: Endpoint,
}

pub struct GossipBuilder {
    topic: Option<GossipTopic>,
    endpoint: Option<Endpoint>,
}

impl GossipBuilder {
    pub fn new() -> Self {
        GossipBuilder {
            topic: None,
            endpoint: None,
        }
    }

    pub fn with_endpoint(mut self, endpoint: &Endpoint) -> Self {
        self.endpoint = Some(endpoint.clone());
        self
    }

    pub fn with_topic(mut self, topic: &GossipTopic) -> Self {
        self.topic = Some(topic.clone());
        self
    }

    pub async fn build(&self) -> Gossip {
        Gossip::new(
            &self.topic.clone().unwrap_or_default(),
            &self
                .endpoint
                .clone()
                .unwrap_or(Endpoint::builder().discovery_n0().bind().await.unwrap()),
        )
    }
}

impl Gossip {
    pub fn new(topic: &GossipTopic, endpoint: &Endpoint) -> Self {
        let gossip = Gossip {
            topic: topic.clone(),
            endpoint: endpoint.clone(),
        };
        gossip.start_discovery();
        gossip
    }

    fn start_discovery(&self) {
        let _self = self.clone();
        tokio::spawn(async move {
            let gossip = _self;
            gossip.discovery_loop().await.is_ok()
        });
    }

    async fn discovery_loop(&self) -> anyhow::Result<()> {
        let pkarr_relay_url = N0_DNS_PKARR_RELAY_PROD;
        let pkarr_client = PkarrRelayClient::new(pkarr_relay_url.parse()?);

        let node_id = self.endpoint.node_id();
        let gossip_info = GossipInfo::new(node_id.clone(), self.topic.clone());
        let node_info = NodeInfo::new(self.topic.to_secret_key().public(), Some(pkarr_relay_url.parse()?), Default::default());


        loop {
            let signed_packet = //node_info.to_pkarr_signed_packet(&self.endpoint.secret_key(), 600)?;
                gossip_info.to_pkarr_signed_packet(&self.topic.to_secret_key(), 600)?;
                println!("!");
            pkarr_client.publish(&signed_packet).await?;
            println!("Published {:?}",signed_packet);
            sleep(Duration::from_secs(300)).await;
        }

        Ok(())
    }

    pub async fn inquery(&self, topic: &GossipTopic) -> anyhow::Result<Vec<NodeId>> {
        let (resolver, origin) = (
            iroh::dns::default_resolver(),
            N0_DNS_NODE_ORIGIN_PROD,
        );
        //println!("Resolver: {:?}",resolver.txt_lookup("iroh-gossip.0a3654a7d0ac898365d4f1e0552a0377.net").await);

        let topic_records = TxtAttrs::<String>::lookup_by_id(&resolver, &topic.to_secret_key().public(),"").await;
        println!("What: {:?}",topic_records);

        Ok(vec![])
    }
}

