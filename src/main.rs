use pqcrypto_ntru::ntruhps2048509::{encrypt, decrypt, keypair};
use std::fs::{File};
use std::io::{Cursor, Read, Write};
use std::path::Path;
use ipfs_api_backend_hyper::{IpfsApi, IpfsClient, TryFromUri};
use blake3::Hasher;
use tokio::runtime::Runtime;

/// Generates an NTRU key pair for encryption.
fn generate_keys() -> (Vec<u8>, Vec<u8>) {
    let (public_key, secret_key) = keypair();
    (public_key.as_bytes().to_vec(), secret_key.as_bytes().to_vec())
}

/// Encrypts data using NTRU encryption.
fn encrypt_data(public_key: &[u8], data: &[u8]) -> Vec<u8> {
    encrypt(public_key, data).expect("Encryption failed")
}

/// Decrypts data using NTRU decryption.
fn decrypt_data(secret_key: &[u8], encrypted_data: &[u8]) -> Vec<u8> {
    decrypt(secret_key, encrypted_data).expect("Decryption failed")
}

/// Computes BLAKE3 hash for quantum-safe integrity.
fn compute_hash(data: &[u8]) -> String {
    let mut hasher = Hasher::new();
    hasher.update(data);
    hasher.finalize().to_hex().to_string()
}

/// Splits a file into shards.
fn shard_file(file_path: &str, shard_size: usize) -> Vec<Vec<u8>> {
    let mut file = File::open(file_path).expect("Failed to open file");
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).expect("Failed to read file");
    buffer.chunks(shard_size).map(|chunk| chunk.to_vec()).collect()
}

/// Uploads file shards to IPFS and returns their hashes.
async fn upload_shards(shards: Vec<Vec<u8>>) -> Vec<(String, String)> {
    let client = IpfsClient::from_str("http://127.0.0.1:5001").unwrap();
    let mut hashes = Vec::new();

    for shard in shards {
        let shard_hash = compute_hash(&shard);
        let response = client.add(Cursor::new(shard)).await.unwrap();
        println!("Shard uploaded: {} -> IPFS Hash: {}", shard_hash, response.hash);
        hashes.push((response.hash, shard_hash));
    }

    hashes
}

/// Verifies if the downloaded shard matches the original hash.
fn verify_shard(original_hash: &str, data: &[u8]) -> bool {
    let computed_hash = compute_hash(data);
    original_hash == computed_hash
}

fn main() {
    let (public_key, secret_key) = generate_keys();
    let data = b"Confidential post-quantum secure storage";

    // Encrypt and decrypt test
    let encrypted = encrypt_data(&public_key, data);
    let decrypted = decrypt_data(&secret_key, &encrypted);
    assert_eq!(data.to_vec(), decrypted);
    println!("Encryption & Decryption successful!");

    // Compute hash of encrypted data
    let encrypted_hash = compute_hash(&encrypted);
    println!("Encrypted data hash: {}", encrypted_hash);

    // Save encrypted data locally
    let file_path = "encrypted_data.bin";
    let mut file = File::create(file_path).expect("Failed to create file");
    file.write_all(&encrypted).expect("Failed to write data");

    // Shard the file
    let shards = shard_file(file_path, 1024);
    println!("File split into {} shards", shards.len());

    // Upload shards to IPFS
    let rt = Runtime::new().unwrap();
    let ipfs_hashes = rt.block_on(upload_shards(shards));
    
    println!("Shards uploaded to IPFS:");
    for (ipfs_hash, original_hash) in &ipfs_hashes {
        println!("Original Hash: {}, IPFS Hash: {}", original_hash, ipfs_hash);
    }

    // Verification process
    println!("Verifying downloaded shards...");
    for (ipfs_hash, original_hash) in ipfs_hashes {
        let client = IpfsClient::from_str("http://127.0.0.1:5001").unwrap();
        let rt = Runtime::new().unwrap();
        let downloaded_data = rt.block_on(client.cat(&ipfs_hash)).unwrap();

        if verify_shard(&original_hash, &downloaded_data) {
            println!("Shard {} verified successfully!", ipfs_hash);
        } else {
            println!("Shard {} verification failed!", ipfs_hash);
        }
    }
}

