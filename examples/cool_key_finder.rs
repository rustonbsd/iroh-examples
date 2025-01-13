use anyhow::Result;
use iroh::{PublicKey, SecretKey};
use iroh_examples::protocols::gossip_info::to_z32;
use rand::rngs::OsRng;

#[tokio::main] 
async fn main() -> Result<()> {

    let mut key_candidates = vec![];
    let mut i: u128 = 0; 
    loop {
        i+=1;
        let (s,p) = gen_secret_key().await;
        if key_candidate((&s,&p)) {
            key_candidates.push((s.clone(),p));
            println!("Key-Candidates {i}: {:?}",(s.to_string(),p.to_string()));
        }
    }

    Ok(())
}

fn key_candidate(keys: (&SecretKey,&PublicKey)) -> bool {
    keys.1.to_string().to_lowercase().starts_with("abcdef")
}

async fn gen_secret_key() -> (SecretKey,PublicKey) {
    let secret = SecretKey::generate(OsRng);
    (secret.clone(),secret.public())
}