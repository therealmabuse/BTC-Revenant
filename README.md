# BTC-Revenant
### BTC REVENANT is a high-speed, multi-threaded Bitcoin key scanner designed to brute-force public keys. This tool is optimized for high-performance systems and is specifically designed to scale across machines with many CPU cores and threads for maximum scanning speed.
---

## ⚙️ Features

- 🔐 **Private Key Discovery** — Generates and tests Bitcoin private keys  
- 🧵 **Full Multithreading** — Automatically uses all CPU threads  
- 🔎 **Targeted Scanning** — Match generated public addresses against known targets  
- 💥 **Legacy + Modern Support** 
- 📈 **Live Stats** — Realtime key count, matches, and speed  
- 📂 **Target Input** — Load Bitcoin public keys from `.txt` file  
- ⚡ **Max Speed** — Built in Rust, zero-prompt runtime execution  

---

## 🛠️ Installation

### 📦 Prerequisites

- Rust (latest stable)  
  → https://www.rust-lang.org/

### 📥 Build

```bash
git clone https://github.com/therealmabuse/btc-revenant.git
cd btc-revenant
cargo build --release
```

Binary will be located at:

```bash
target/release/btc-revenant
```

---

## 🚀 Usage

```bash
cargo run --release
```

## 🔧 Functionality Overview

### 🔑 Key Generation Modes

- **Random**  
  Generates cryptographically secure private keys from system entropy

- **SequentialUp**  
  Brute-force incremental key scan from specified hex range

---

### 📊 Live Output Example

```text
[+] Scanned Keys: 4,219,330
[+] Matches Found: 0
[+] Current Key: f4cc...2a6e
[+] Speed: 960,000 keys/sec
```

---

## 🧪 Target File Format

Files with more than 127.000 rows have been tested, and work fine.
`btcpublickeys.txt` should contain one address per line:

```txt
02000169760462c57b16cf149225563733494c65994ba569d42c802c6fadadcc2d
031fd49e54b6b398e2b11d0ae156c3f8cd5c2a0ebd593487f11852c02d7e9830e6
02000251b7acfa505fc4086d69d404105c6e27a74a86a0fc0ff5fadaaec4819faa
0200029f1dc5dbbad6805da36cc64fa5b751069944556c6e1c051d328d62fb8619
```

---

## 🧱 Dependencies

- [`bitcoin`](https://crates.io/crates/bitcoin)  
- [`bip39`](https://crates.io/crates/bip39)  
- [`secp256k1`](https://docs.rs/secp256k1)  
- [`rayon`](https://crates.io/crates/rayon) 

---

## 🧠 Notes

- Fully offline-capable  
- No external API dependencies  
- No telemetry  
- Efficient address matching via hashed sets  
- Optimized for continuous high-speed scanning  

---

## ⚠️ Disclaimer

> **This tool is for research and educational purposes only.**  
> Unauthorized access or use of private keys is illegal.  
> The author assumes no responsibility for misuse or legal consequences.



