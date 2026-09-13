# 🛡️ Crypto NRD Threat Feed | HackProtect Labs

Automated Cyber Threat Intelligence (CTI) feed tracking Newly Registered Domains (NRDs) targeting the Web3, cryptocurrency, and decentralized finance (DeFi) ecosystems.

## 🎯 Objective
Phishing campaigns in the crypto space rely heavily on newly registered domains to impersonate popular exchanges, DEX platforms, staking portals, and wallet providers. This repository provides a near real-time intelligence feed to help security analysts, SOC teams, and Web3 projects proactively block malicious infrastructure before attacks materialize.

---

## 📊 Feed Structure & Format

The data is automatically processed, filtered for false positives, and updated regularly as a plain text blocklist. 

- **Format:** Plain text, one domain per line (fully compatible with firewall Custom Categories, Pi-hole, DNS sinks, and custom scripts)
- **Update Frequency:** Automated daily ingestion
- **Classification:** TLP:CLEAR (Public sharing permitted)

---

## 🚀 Usage & Integration

You can easily ingest this plain text feed into your security controls using `curl`:

```bash
curl -s https://raw.githubusercontent.com/hack-protect-labs/crypto-nrd-feed/refs/heads/main/feed/domains.txt
```

---

## 🛑 False Positives & Domain Removal

We strive to maintain high accuracy and minimize false positives. However, if you are a domain owner, administrator, or security researcher and believe a legitimate domain has been incorrectly flagged and included in this feed, please report it immediately.

To request a review or removal of a domain:
- Open an **Issue** in this repository with the subject `False Positive: [domain-name.com]`, or
- Reach out directly via X (Twitter): [@HackProtectLabs](https://x.com/HackProtectLabs)

We will review and remove verified false positives promptly.

---

## ⚠️ Disclaimer
This feed is provided for defensive security purposes, threat hunting, and research only. The indicators listed are compiled from automated OSINT sources and certificate transparency logs. 

---
*Maintained by [HackProtect Labs](https://x.com/HackProtectLabs).*
