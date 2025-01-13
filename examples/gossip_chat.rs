use std::{collections::HashMap, net::{Ipv4Addr, SocketAddrV4}, str::FromStr, thread::sleep, time::Duration};

use anyhow::bail;
use bytes::Bytes;
use ed25519_dalek::Signature;
use iroh::{discovery::{dns::DnsDiscovery, pkarr::{dht::DhtDiscovery, PkarrRelayClient}, ConcurrentDiscovery}, endpoint, Endpoint, NodeAddr, NodeId, PublicKey, RelayUrl, SecretKey};
use iroh_blobs::{net_protocol::Blobs, util::local_pool::{self, LocalPool}};
use iroh_docs::protocol::Docs;
use iroh_examples::protocols::{gossip_info::GossipTopic, gossip_topic_discovery::GossipBuilder};
use iroh_gossip::{net::{Event, Gossip, GossipEvent, GossipReceiver, GossipSender}, proto::TopicId};
use serde::{Deserialize, Serialize};
use futures_lite::stream::StreamExt;


#[tokio::main]
async fn main() -> anyhow::Result<()> {

    let topic_id = TopicId::from_bytes([37u8;32]);
    let secret_key =  SecretKey::generate(rand::rngs::OsRng);
    
    let discovery = DnsDiscovery::n0_dns();
    let endpoint = Endpoint::builder()
        .secret_key(secret_key)
        .discovery_n0()
        .discovery(Box::new(discovery))
        .bind()
        .await?;
    
    let local_pool = LocalPool::default();
    let blobs = Blobs::memory().build(local_pool.handle(), &endpoint);

    let gossip = Gossip::builder().spawn(endpoint.clone()).await.unwrap();
    
    let docs = Docs::memory().spawn(&blobs, &gossip).await?;

    let router = iroh::protocol::Router::builder(endpoint.clone())
        .accept(iroh_gossip::ALPN, gossip.clone())
        .accept(iroh_blobs::ALPN, blobs.clone())
        .accept(iroh_docs::ALPN, docs.clone())
        .spawn()
        .await?;

    
    /*
    let gossip_topic = GossipTopic::from_passphrase("thisisatest");
    println!("TOPIC: OGOOE: {}",gossip_topic.to_string());
    let owngoss = GossipBuilder::new().with_endpoint(&endpoint).with_topic(&gossip_topic).build().await;

    loop {
        let _ = owngoss.inquery(&gossip_topic).await;
        sleep(Duration::from_secs(2));
    }*/

    println!("NodeId: {:?}",endpoint.node_addr().await);
    println!("Joining gossip sup..");
    //let node_id_bytes = hex::decode("50211f29668e5e6d21fd232ef353ed01afef2422b6afb847f1e92d8f7c1cd23f")?;
    //let node_id = NodeId::try_from(node_id_bytes.as_slice())?;
    //endpoint.add_node_addr(NodeAddr::from_parts(node_id, Some(RelayUrl::from_str("https://euw1-1.relay.iroh.network./")?),vec![]))?;
    //println!("endpoint");
    //let (mut sender, receiver) = gossip.subscribe(topic_id, vec![]).unwrap().split();
    let (mut sender, receiver) = gossip.subscribe_and_join(topic_id, vec![]).await.unwrap().split();

    // Start peer message handler
    println!("starting peer message handler..");
    tokio::spawn(async move { peer_message_handler(receiver).await.is_ok() });

    // Send initial message
    let init_message = Message::Init { node_id: endpoint.node_id().to_string() };    
    if send_message(&mut sender, &endpoint.secret_key(), &init_message).await.is_err() {
        bail!("failed to send init message!")
    }

    // broadcast each line we type
    let (line_tx, mut line_rx) = tokio::sync::mpsc::channel(1);
    std::thread::spawn(move || input_loop(line_tx));

    println!("> type a message and hit enter to broadcast...");
    while let Some(text) = line_rx.recv().await {
        let message = Message::Text { text: text.clone() };
        match send_message(&mut sender, &endpoint.secret_key(), &&message).await {
            Ok(_) => {
                println!("Send message successfully!");
            },
            Err(_) => {
                println!("Failed to send message!");
                continue
            },
        }
        println!("> sent: {text}");
    }

    router.shutdown().await?;

    Ok(())

}

async fn send_message(sender: &mut GossipSender,secret_key: &SecretKey, message: &Message) -> anyhow::Result<()> {
    let signed_message = message.sign(secret_key)?;
    sender.broadcast(signed_message.to_bytes()?).await?;
    Ok(())
}

async fn peer_message_handler(mut receiver: GossipReceiver) -> anyhow::Result<()>{
    let mut connected_nodes = HashMap::new();

    loop {
        println!("Loop!");
        let event = match receiver.try_next().await {
            Ok(event) => match event { Some(event) => event, None => continue},
            Err(_) => continue,
        };

        println!("Event: {:?}",event);

        match event {
            Event::Gossip(gossip_event) => match gossip_event {
                GossipEvent::Joined(vec) => { println!("Joined: {:?}", vec)},
                GossipEvent::NeighborUp(public_key) => { println!("NeighborUp: {:?}", public_key)},
                GossipEvent::NeighborDown(public_key) =>  { println!("NeighborDown: {:?}", public_key)},
                GossipEvent::Received(message) => {

                    println!("recv msg: {message:?}");
                    
                    // Message received
                    let (from, msg) = match SignedMessage::verify_and_decode(&message.content) {
                        Ok((from, msg)) => (from,msg),
                        Err(err) => {
                            println!("Received: {err}");
                            continue
                        },
                    };

                    match msg {
                        Message::Init { node_id } => {
                            connected_nodes.insert(from, node_id);
                        },
                        Message::Text { text } => {
                            println!("Message: {text}");
                        },
                    }
                },
            },
            Event::Lagged => { println!("Lagged: -"); },
        }
    }
    Ok(())
} 

fn input_loop(line_tx: tokio::sync::mpsc::Sender<String>) -> anyhow::Result<()> {
    let mut buffer = String::new();
    let stdin = std::io::stdin(); // We get `Stdin` here.
    loop {
        stdin.read_line(&mut buffer)?;
        line_tx.blocking_send(buffer.clone())?;
        buffer.clear();
    }
}

impl Message {
    pub fn sign(&self,secret_key: &SecretKey) -> anyhow::Result<SignedMessage> {
        SignedMessage::from_message(secret_key, self)
    }
}

#[derive(Debug, Serialize, Deserialize)]
enum Message {
    Init { node_id: String },
    Text { text: String },
}

#[derive(Debug, Serialize, Deserialize)]
struct SignedMessage {
    from: PublicKey,
    data: Bytes,
    signature: Signature,
}

impl SignedMessage {
    pub fn from_message(secret_key: &SecretKey, message: &Message) -> anyhow::Result<Self> {
        Self::sign(secret_key,message)
    }

    pub fn to_message(&self) -> anyhow::Result<Message> {
        let (_,message) = Self::verify(self)?;
        Ok(message)
    }

    pub fn get_signer(&self) -> anyhow::Result<PublicKey> {
        let (public_key,_) = Self::verify(self)?;
        Ok(public_key)
    }

    pub fn encode(signed_message: &Self) -> anyhow::Result<Bytes> {
        Ok(postcard::to_stdvec(&signed_message)?.into())
    }

    pub fn to_bytes(&self) -> anyhow::Result<Bytes> {
        Self::encode(self)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self,anyhow::Error> {
        match postcard::from_bytes::<Self>(&bytes) {
            Ok(signed_message) => Ok(signed_message),
            Err(err) => bail!("failed to decode signed message: {err}"),
        }
    }

    pub fn sign(secret_key: &SecretKey, message: &Message) -> anyhow::Result<Self> {
        let data: Bytes = postcard::to_stdvec(&message)?.into();
        let signature = secret_key.sign(&data);
        let from: PublicKey = secret_key.public();
        Ok(Self {
            from,
            data,
            signature,
        })
    }

    pub fn verify(signed_message: &Self) -> anyhow::Result<(PublicKey,Message)> {
        let key: PublicKey = signed_message.from;
        key.verify(&signed_message.data, &signed_message.signature)?;
        let message: Message = postcard::from_bytes(&signed_message.data)?;
        Ok((key,message))
    }

    pub fn verify_and_decode(bytes: &[u8]) -> anyhow::Result<(PublicKey, Message)> {
        let signed_message: Self = postcard::from_bytes(bytes)?;
        Self::verify(&signed_message)
    }

    pub fn sign_and_encode(secret_key: &SecretKey, message: &Message) -> anyhow::Result<Bytes> {
        let signed_message = Self::sign(secret_key, message)?;
        Self::encode(&signed_message)
    }

}