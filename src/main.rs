use secp256k1::{Secp256k1, SecretKey, PublicKey, All};
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use std::time::{Duration, Instant};
use crossbeam::scope;
use num_cpus;
use num_bigint::BigUint;
use hex;
use std::cmp;
use core_affinity;
use std::thread;
use bloom::{BloomFilter, ASMS};

fn print_banner() {
    // ANSI color codes
    let magenta = "\x1b[35m";
    let cyan = "\x1b[36m";
    let green = "\x1b[32m";
    let reset = "\x1b[0m";

    println!("{}══════════════════════════════════════{}", magenta, reset);
    println!("{}{}   {}BTC REVENΔNT{} by {}MΔBUSΞ{}         {}{}", 
        magenta, reset, cyan, reset, green, reset, magenta, reset);
    println!("{}{}   {}Bitcoin Public Key Scanner{}      {}{}", 
        magenta, reset, cyan, reset, magenta, reset);
    println!("{}══════════════════════════════════════{}", magenta, reset);
    println!();
}

#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

type PubKeyFilter = BloomFilter;

#[inline(always)]
fn get_pubkey_bytes(secret_key: &SecretKey, secp: &Secp256k1<All>, buffer: &mut [u8; 33]) {
    let pubkey = PublicKey::from_secret_key(secp, secret_key);
    buffer.copy_from_slice(&pubkey.serialize());
}

fn load_target_pubkeys(path: &str) -> io::Result<PubKeyFilter> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut line = String::new();

    let mut filter = BloomFilter::with_size(51_200_000_000, 7); // ~6GB memory

    while reader.read_line(&mut line)? > 0 {
        let cleaned = line.trim().to_lowercase();
        if cleaned.len() == 66 {
            if let Ok(decoded) = hex::decode(&cleaned) {
                if decoded.len() == 33 {
                    filter.insert(&decoded);
                }
            }
        }
        line.clear();
    }

    Ok(filter)
}

fn prompt_input(label: &str) -> String {
    print!("{label}: ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

fn hex_to_u256(hex: &str) -> Result<[u8; 32], &'static str> {
    let hex = hex.trim_start_matches("0x");
    let bytes = hex::decode(hex).map_err(|_| "Invalid hex")?;
    if bytes.len() > 32 {
        return Err("Hex too long");
    }
    let mut buf = [0u8; 32];
    buf[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(buf)
}

fn u256_to_u64_array(buf: [u8; 32]) -> [u64; 4] {
    [
        u64::from_be_bytes(buf[0..8].try_into().unwrap()),
        u64::from_be_bytes(buf[8..16].try_into().unwrap()),
        u64::from_be_bytes(buf[16..24].try_into().unwrap()),
        u64::from_be_bytes(buf[24..32].try_into().unwrap()),
    ]
}

fn u64_array_to_scalar(arr: [u64; 4]) -> BigUint {
    let mut result = BigUint::from(0u32);
    for (i, part) in arr.iter().enumerate() {
        result += BigUint::from(*part) << (64 * (3 - i));
    }
    result
}

fn format_biguint_hex(num: &BigUint) -> String {
    let bytes = num.to_bytes_be();
    let mut hex_str = hex::encode(bytes);
    if hex_str.len() < 64 {
        hex_str = format!("{:0>64}", hex_str);
    }
    hex_str
}

fn process_batch(
    start: BigUint,
    end: BigUint,
    target_pubkeys: &PubKeyFilter,
    secp: &Secp256k1<All>,
    found_flag: Arc<AtomicBool>,
    counter: Arc<Mutex<u64>>,
    current_key: Arc<Mutex<BigUint>>,
) -> Option<(String, String)> {
    let mut current = start;
    let one = BigUint::from(1u32);
    let mut buf = [0u8; 32];
    let mut pubkey_buf = [0u8; 33];

    while current <= end && !found_flag.load(Ordering::Relaxed) {
        let batch_end = cmp::min(&current + BigUint::from(10_000u32), end.clone());
        let mut local_count = 0u64;

        let mut k = current.clone();
        while k <= batch_end {
            let bytes = k.to_bytes_be();
            if bytes.len() > 32 {
                k += &one;
                continue;
            }

            buf[32 - bytes.len()..].copy_from_slice(&bytes);

            if let Ok(secret_key) = SecretKey::from_byte_array(buf) {
                get_pubkey_bytes(&secret_key, secp, &mut pubkey_buf);

                if target_pubkeys.contains(&pubkey_buf) {
                    found_flag.store(true, Ordering::Relaxed);
                    return Some((hex::encode(buf), hex::encode(pubkey_buf)));
                }
            }

            local_count += 1;
            k += &one;
        }

        *current_key.lock().unwrap() = batch_end.clone();
        *counter.lock().unwrap() += local_count;
        current = batch_end + &one;
    }
    None
}

fn display_stats(
    counter: Arc<Mutex<u64>>,
    start_time: Instant,
    running: Arc<AtomicBool>,
    current_key: Arc<Mutex<BigUint>>,
    start_scalar: Arc<BigUint>,
    end_scalar: Arc<BigUint>,
) {
    thread::spawn(move || {
        let mut last_print = Instant::now();
        while running.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_secs(1));

            let elapsed = start_time.elapsed().as_secs();
            let count = *counter.lock().unwrap();
            let current = current_key.lock().unwrap().clone();

            if last_print.elapsed().as_secs() >= 45 || count % 1_000_000 == 0 {
                let total_range = (&*end_scalar).clone() - (&*start_scalar).clone();
                let progress = (current.clone() - (&*start_scalar).clone()) * BigUint::from(100u32) / total_range;
                let keys_per_sec = count as f64 / elapsed as f64;

                println!(
                    "\n[Status Update @ {}s]\n\
                    Progress: {}%\n\
                    Current Key: 0x{}\n\
                    Keys Scanned: {}\n\
                    Speed: {:.2} keys/s\n\
                    Start Range: 0x{}\n\
                    End Range: 0x{}",
                    elapsed,
                    progress,
                    format_biguint_hex(&current),
                    count,
                    keys_per_sec,
                    format_biguint_hex(&*start_scalar),
                    format_biguint_hex(&*end_scalar)
                );

                last_print = Instant::now();
            }
        }
    });
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    print_banner();
    let core_ids = core_affinity::get_core_ids().unwrap_or_else(|| {
        println!("Warning: Could not get core IDs, running without core affinity");
        vec![]
    });
    let num_cores = num_cpus::get();
    println!("Detected {} CPU cores", num_cores);

    if !core_ids.is_empty() && core_ids.len() < num_cores {
        eprintln!("Warning: fewer cores available for affinity pinning than detected CPUs");
    }

    let secp = Secp256k1::new();

    let pubkey_file = prompt_input("Enter path to public keys txt file");
    let start_hex = prompt_input("Enter start hex (private key)");
    let end_hex = prompt_input("Enter end hex (private key)");

    let target_pubkeys = load_target_pubkeys(&pubkey_file)?;
    println!("Loaded Bloom filter with target pubkeys.");

    let start_scalar = u64_array_to_scalar(u256_to_u64_array(hex_to_u256(&start_hex)?));
    let end_scalar = u64_array_to_scalar(u256_to_u64_array(hex_to_u256(&end_hex)?));

    if start_scalar > end_scalar {
        return Err("Invalid range: start must be less than end".into());
    }

    let total_keys = (&end_scalar).clone() - (&start_scalar).clone();
    println!("Total keys to scan: {}", total_keys);

    let found_flag = Arc::new(AtomicBool::new(false));
    let counter = Arc::new(Mutex::new(0u64));
    let current_key = Arc::new(Mutex::new(start_scalar.clone()));
    let running = Arc::new(AtomicBool::new(true));

    let start_time = Instant::now();
    let start_scalar_arc = Arc::new(start_scalar.clone());
    let end_scalar_arc = Arc::new(end_scalar.clone());

    display_stats(
        counter.clone(),
        start_time,
        running.clone(),
        current_key.clone(),
        start_scalar_arc.clone(),
        end_scalar_arc.clone(),
    );

    let core_ids_arc = Arc::new(core_ids);

    let result = scope(|s| {
        let batch_size = (&end_scalar - &start_scalar) / num_cores as u32;
        let mut current = start_scalar.clone();
        let mut handles = vec![];

        for i in 0..num_cores {
            let batch_end = if i == num_cores - 1 {
                end_scalar.clone()
            } else {
                cmp::min(&current + &batch_size, end_scalar.clone())
            };
            let batch = (current.clone(), batch_end.clone());
            let secp = &secp;
            let target_pubkeys = &target_pubkeys;
            let found_flag = found_flag.clone();
            let counter = counter.clone();
            let current_key = current_key.clone();
            let core_ids = core_ids_arc.clone();

            handles.push(s.spawn(move |_| {
                if let Some(core) = core_ids.get(i) {
                    if core_affinity::set_for_current(*core) {
                        println!("Thread {} pinned to core {}", i, core.id);
                    }
                }
                process_batch(
                    batch.0,
                    batch.1,
                    target_pubkeys,
                    secp,
                    found_flag,
                    counter,
                    current_key,
                )
            }));

            current = batch_end + BigUint::from(1u32);
        }

        let mut result = None;
        for handle in handles {
            if let Some(found) = handle.join().unwrap() {
                result = Some(found);
                break;
            }
        }
        result
    }).unwrap();

    running.store(false, Ordering::Relaxed);
    thread::sleep(Duration::from_secs(1));

    if let Some((privkey, pubkey)) = result {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open("found.txt")?;
        writeln!(file, "Private: 0x{}\nPublic:  {}", privkey, pubkey)?;
        println!("\nMatch found!\nPrivate: 0x{}\nPublic:  {}", privkey, pubkey);
    } else {
        println!("\nNo matches found in the specified range.");
    }

    let elapsed = start_time.elapsed().as_secs_f64();
    let total_scanned = *counter.lock().unwrap();
    println!("Total keys scanned: {}", total_scanned);
    println!("Average speed: {:.2} keys/s", total_scanned as f64 / elapsed);
    println!("Total time: {:.2} seconds", elapsed);

    Ok(())
}