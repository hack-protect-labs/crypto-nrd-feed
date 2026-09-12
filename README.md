# 🛡️ Crypto NRD Threat Feed | HackProtect Labs

Automated Cyber Threat Intelligence (CTI) feed tracking Newly Registered Domains (NRDs) targeting the Web3, cryptocurrency, and decentralized finance (DeFi) ecosystems.

## 🎯 Objective
Phishing campaigns in the crypto space rely heavily on newly registered domains to impersonate popular exchanges, DEX platforms, staking portals, and wallet providers. This repository provides a near real-time, structured intelligence feed to help security analysts, SOC teams, and Web3 projects proactively block malicious infrastructure before attacks materialize.

---

## 📊 Feed Structure & Format

The data is automatically processed, filtered for false positives, and updated regularly. 

- **File Path:** `/feed/active-crypto-nrd.json`
- **Update Frequency:** Automated daily ingestion
- **Classification:** TLP:CLEAR (Public sharing permitted)

### JSON Schema Example
```json
{
  "timestamp": "2026-09-13T01:30:00Z",
  "domain": "example-crypto-staking-login.com",
  "registrar": "Namecheap, Inc.",
  "creation_date": "2026-09-12T14:22:10Z",
  "targeted_brand": "Generic DEX / Web3 Wallet",
  "risk_score": "HIGH",
  "asn": "13335 (Cloudflare, Inc.)"
}
