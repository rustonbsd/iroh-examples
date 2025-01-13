use futures_lite::StreamExt;
use iroh::dns::node_info::from_z32;
use iroh_docs::engine::LiveEvent;
use iroh_docs::{ContentStatus, DocTicket, NamespaceSecret};
use iroh_examples::protocols::gossip_info::to_z32;
use iroh_examples::protocols::shared_doc::{GossipTable, GossipTopic};
use iroh_examples::iroh::Iroh;
use iroh::NodeAddr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {

    let iroh = Iroh::new("./data3".into()).await?;
    let node_id = iroh.clone().get_endpoint().node_id();
    let topic = GossipTopic::from_passphrase("mypassphrase");
    let ticket = DocTicket { 
        capability: iroh_docs::Capability::Write(NamespaceSecret::from_bytes(&topic.to_secret_key().to_bytes())), 
        nodes: vec![NodeAddr::new(node_id)], //,NodeAddr::new(from_z32("ggh95h5oejfiretokub6565oy53rzi1mcgmztwmgx4gdcwxzsk4o").unwrap())],
    };
    let mut gossip_table = GossipTable::new(Some(ticket.to_string()), iroh).await?;
    
    let mut events = gossip_table.doc_subscribe().await?;
    
    let add_entry = gossip_table.add("1".to_string(), to_z32(&node_id), topic.to_string()).await;
    println!("Added entry: {add_entry:?}");

    //tokio::spawn(async move {
        while let Some(Ok(event)) = events.next().await {
            match event {
                LiveEvent::InsertRemote { content_status, entry: _, from } => {
                    // Only update if the we already have the content. Likely to happen when a remote user toggles "done".
                    if content_status == ContentStatus::Complete {
                        println!("Discovered new node id: {}",to_z32(&from));
                    }
                }
                LiveEvent::InsertLocal { .. } | LiveEvent::ContentReady { .. } => {
                    println!("Local changes");
                }
                other => {println!("Other-Event: {:?}",other);}
            }
        }
    //});



    Ok(())
}