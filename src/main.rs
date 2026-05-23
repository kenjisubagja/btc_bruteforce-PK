// ============================================================
// BTC Private Key Generator & Balance Checker - Rust Edition
// For AUTHORIZED security testing only.
// ============================================================

use chrono::Local;
use rand::RngCore;
use rayon::prelude::*;
use secp256k1::{rand, Secp256k1, SecretKey, PublicKey};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

// ============================================================
// CONSTANTS
// ============================================================
const OUTPUT_FILE: &str = "found_wallets.txt";
const API_ENDPOINT: &str = "https://blockchain.info/balance?active=";

// ============================================================
// STATISTICS (Atomic untuk thread-safe)
// ============================================================
struct Stats {
    checked: AtomicU64,
    found: AtomicU64,
    errored: AtomicU64,
}

impl Stats {
    fn new() -> Self {
        Self {
            checked: AtomicU64::new(0),
            found: AtomicU64::new(0),
            errored: AtomicU64::new(0),
        }
    }
}

// ============================================================
// CORE CRYPTO FUNCTIONS
// ============================================================

fn generate_private_key() -> SecretKey {
    let mut rng = rand::thread_rng();
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    SecretKey::from_slice(&seed).expect("32 bytes, within curve order")
}

fn private_key_to_address(secp: &Secp256k1<secp256k1::All>, secret: &SecretKey) -> (String, String) {
    // Derive public key (compressed)
    let public_key = PublicKey::from_secret_key(secp, secret);
    let pub_key_serialized = public_key.serialize().to_vec(); // 33 bytes compressed
    
    // SHA256
    let sha256 = Sha256::digest(&pub_key_serialized);
    
    // RIPEMD160
    let ripemd = ripemd::Ripemd160::digest(&sha256);
    
    // Address payload: 0x00 (mainnet) + RIPEMD160 hash
    let mut payload = vec![0x00u8];
    payload.extend_from_slice(&ripemd);
    
    // Double SHA256 untuk checksum
    let hash1 = Sha256::digest(&payload);
    let hash2 = Sha256::digest(&hash1);
    
    // Add first 4 bytes of checksum
    let mut address_bytes = payload;
    address_bytes.extend_from_slice(&hash2[..4]);
    
    // Base58 encode
    let address = bs58::encode(&address_bytes).into_string();
    
    // WIF (Wallet Import Format)
    let secret_bytes = secret.as_ref();
    let mut wif_payload = vec![0x80u8]; // Mainnet
    wif_payload.extend_from_slice(secret_bytes);
    wif_payload.push(0x01); // Compressed flag
    
    let hash1_wif = Sha256::digest(&wif_payload);
    let hash2_wif = Sha256::digest(&hash1_wif);
    wif_payload.extend_from_slice(&hash2_wif[..4]);
    
    let wif = bs58::encode(&wif_payload).into_string();
    
    (address, wif)
}

// ============================================================
// BALANCE CHECKER
// ============================================================

fn check_balance(address: &str) -> Result<(f64, u64), String> {
    let url = format!("{}{}", API_ENDPOINT, address);
    
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .user_agent("Mozilla/5.0")
        .build()
        .map_err(|e| format!("Client error: {}", e))?;
    
    let resp = client
        .get(&url)
        .send()
        .map_err(|e| format!("Request error: {}", e))?;
    
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    
    let json: serde_json::Value = resp
        .json()
        .map_err(|e| format!("JSON parse error: {}", e))?;
    
    if let Some(obj) = json.get(address) {
        let balance_satoshi = obj["final_balance"].as_u64().unwrap_or(0);
        let tx_count = obj["n_tx"].as_u64().unwrap_or(0);
        Ok((balance_satoshi as f64 / 100_000_000.0, tx_count))
    } else {
        Err("Address not found in response".to_string())
    }
}

// ============================================================
// SAVE TO FILE
// ============================================================

fn save_wallet(address: &str, wif: &str, secret_hex: &str, balance: f64, tx_count: u64) {
    let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let entry = format!(
        "============================================================\n\
         [+] FOUND WALLET WITH BALANCE! ({timestamp})\n\
         ============================================================\n\
         Private Key (Hex): {secret_hex}\n\
         Private Key (WIF):  {wif}\n\
         Address:           {address}\n\
         Balance:           {balance:.8} BTC\n\
         Transactions:      {tx_count}\n\
         ============================================================\n\n"
    );
    
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(OUTPUT_FILE)
        .expect("Cannot open output file");
    
    file.write_all(entry.as_bytes()).expect("Cannot write to file");
}

// ============================================================
// WORKER FUNCTION (dijalankan di thread pool)
// ============================================================

fn worker_process(stats: &Stats, file_mutex: &Mutex<()>) {
    let secp = Secp256k1::new();
    
    loop {
        // Generate key pair
        let secret = generate_private_key();
        let (address, wif) = private_key_to_address(&secp, &secret);
        let secret_hex = hex::encode(secret.as_ref());
        
        // Increment counter
        stats.checked.fetch_add(1, Ordering::Relaxed);
        
        // Check balance
        match check_balance(&address) {
            Ok((balance, tx_count)) => {
                if balance > 0.0 {
                    stats.found.fetch_add(1, Ordering::Relaxed);
                    
                    // Lock file untuk write (hanya 1 thread at a time)
                    let _lock = file_mutex.lock().unwrap();
                    save_wallet(&address, &wif, &secret_hex, balance, tx_count);
                    
                    println!(
                        "\n{}[!!!] FOUND! Address: {} | Balance: {:.8} BTC{}",
                        "\x1b[32m", address, balance, "\x1b[0m"
                    );
                }
            }
            Err(e) => {
                stats.errored.fetch_add(1, Ordering::Relaxed);
                if stats.errored.load(Ordering::Relaxed) % 100 == 0 {
                    eprintln!("[!] API Error ({}): {}", stats.errored.load(Ordering::Relaxed), e);
                }
            }
        }
    }
}

// ============================================================
// PROGRESS REPORTER
// ============================================================

fn progress_reporter(stats: &Stats, start: Instant) {
    loop {
        std::thread::sleep(std::time::Duration::from_secs(5));
        
        let checked = stats.checked.load(Ordering::Relaxed);
        let found = stats.found.load(Ordering::Relaxed);
        let elapsed = start.elapsed().as_secs_f64();
        let rate = checked as f64 / elapsed;
        
        println!(
            "\r[{}] Checked: {} | Found: {} | Rate: {:.0} keys/sec | Elapsed: {:.1}s",
            Local::now().format("%H:%M:%S"),
            checked,
            found,
            rate,
            elapsed,
        );
    }
}

// ============================================================
// MAIN
// ============================================================

fn main() {
    println!("╔══════════════════════════════════════════════════╗");
    println!("║   BTC Private Key Checker - Rust Edition        ║");
    println!("║   For AUTHORIZED Security Testing Only          ║");
    println!("╚══════════════════════════════════════════════════╝");
    println!();
    
    // Detect CPU cores
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    
    println!("[*] CPU Cores detected: {}", cores);
    println!("[*] Threads:            {}", cores);
    println!("[*] Output file:        {}", OUTPUT_FILE);
    println!("[*] Starting at:        {}", Local::now().format("%H:%M:%S"));
    println!("[*] {}...\n", "=".repeat(50));
    
    let stats = Arc::new(Stats::new());
    let file_mutex = Arc::new(Mutex::new(()));
    let start = Instant::now();
    
    // Start progress reporter thread
    let stats_reporter = Arc::clone(&stats);
    std::thread::spawn(move || {
        progress_reporter(&stats_reporter, start);
    });
    
    // Start worker threads menggunakan Rayon thread pool
    let stats_workers = Arc::clone(&stats);
    let file_mutex_workers = Arc::clone(&file_mutex);
    
    (0..cores).into_par_iter().for_each(|_| {
        worker_process(&stats_workers, &file_mutex_workers);
    });
    
    // Program runs indefinitely until Ctrl+C
    loop {
        std::thread::sleep(std::time::Duration::from_secs(60));
    }
}