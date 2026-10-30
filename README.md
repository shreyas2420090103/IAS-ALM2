# CryptoShield — Cybersecurity Learning Suite

**Adapted and maintained by:** T Shreyas Reddy
**Original author:** Trinadh Koundinya V
**Original author roll number:** 2420090121
**Department:** CSE
**Course:** Information Assurance and Security (ALM-2)

> This repository is an adaptation of the original CryptoShield ALM-2 project by Trinadh Koundinya V. Original authorship is acknowledged; this copy is maintained by T Shreyas Reddy.

A React + Flask + SQLite academic project adapted for ALM-2 that implements **all three** ALM-2 projects from the course spec: CryptoVault, SecureTunnel and Sentinel. Built from scratch with a custom emerald/indigo visual theme.

## Folder layout

```text
IAS_alm2/
├── Sentinel-backend-new/
│   ├── app.py
│   └── requirements.txt
├── Sentinel-frontend-new/
│   ├── src/
│   │   ├── main.jsx
│   │   └── style.css
│   ├── index.html
│   ├── package.json
│   └── vite.config.js
├── backend/
│   ├── app.py
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── main.jsx
│   │   └── style.css
│   ├── index.html
│   ├── package.json
│   └── vite.config.js
├── .gitignore
└── README.md
```

The `backend/` and `frontend/` folders are the primary application. `Sentinel-backend-new/`
and `Sentinel-frontend-new/` are identical self-contained copies included to match the
four-folder reference layout. Run only one backend/frontend pair at a time to avoid port
conflicts.

## Modules and features

### 1. CryptoVault — Public-Key Cryptography & Digital Signatures
- Register/login with PBKDF2-salted passwords; RSA-2048 key pair generated on registration.
- Private key shown once, never stored server-side.
- Public key directory and downloadable self-signed X.509 certificates (30-day validity).
- RSA-OAEP(SHA-256) encrypt/decrypt and RSA-PSS(SHA-256) sign/verify with pasted PEM keys.
- SHA-512 digest display.
- Diffie-Hellman step-by-step exchange visualization (Alice and Bob panels).
- ElGamal digital signatures with sign/verify, including a "tamper & verify" demonstration
  that proves the signature fails when the message is modified.
- Note: DH and ElGamal use small illustrative parameters (prime 7919) for classroom
  arithmetic. Never use for real cryptographic protection.

### 2. SecureTunnel — TLS/SSH/IPsec Visualizer
- Server-side stateful TLS 1.3 handshake timeline (ClientHello, ServerHello, certificate
  authentication, ephemeral key agreement, Finished) — step-through with "Next step".
- Simplified SSH handshake sequence: version exchange, algorithm negotiation, DH key
  exchange, host authentication, user authentication, encrypted session.
- Interactive IPsec ESP packet diagram that toggles between Transport and Tunnel modes,
  highlighting which packet fields are encrypted.
- Note: these visualizers describe protocol sequencing; they do not create a real TLS/SSH
  network connection.

### 3. Sentinel — Intrusion Detection & Firewall Simulator
- SQLite-backed firewall rule manager: add/delete rules by source/destination IP or CIDR,
  port, protocol (TCP/UDP/ICMP/any) and action (ALLOW/BLOCK).
- Simulated packet engine: newest matching rule wins, default ALLOW.
- Rule-based IDS: Telnet on port 23 is flagged; five failed SSH logins in a rolling
  60-second window triggers an alert.
- Statistical anomaly IDS: monitors traffic volume per source IP and fires when a new
  sample exceeds mean + 3 × max(std dev, 1) after at least five samples.
- Dashboard with a Recharts time-series of traffic volume, alert feed, packet log and
  a bastion-host concept entry.
- Static threat encyclopedia: file infector virus, boot sector virus, email worm,
  network worm, bastion host — each with a recommended defense.

## Requirements
- Python 3.10+ and pip
- Node.js 18+ and npm

## Run locally

**Terminal 1 (backend)**

```bash
cd backend
python -m pip install -r requirements.txt
python app.py
```

The Flask backend runs at `http://127.0.0.1:5000`. The SQLite database
(`cryptoshield.sqlite3`) is created automatically.

**Terminal 2 (frontend)**

```bash
cd frontend
npm install
npm run dev
```

Open `http://127.0.0.1:5173`. Keep both terminals running. The Vite dev server proxies
`/api` requests to Flask.

## Demo walkthrough

1. CryptoVault → Account: register a demo user with a throwaway password. **Copy the
   private key** that appears; it is never recoverable.
2. CryptoVault → RSA: paste the public key to encrypt a message, then paste the private
   key and the ciphertext to decrypt. Sign with the private key and verify with the
   public key.
3. CryptoVault → Diffie-Hellman: click "New exchange" — Alice and Bob derive the same
   shared secret.
4. CryptoVault → ElGamal: sign a message, verify it (valid), then click
   "Tamper & verify" (invalid — this is why hashing before signing matters).
5. SecureTunnel: start the TLS handshake and click "Next step" through all five stages;
   repeat for SSH; toggle IPsec transport/tunnel modes.
6. Sentinel → Firewall: add a BLOCK rule for `*` → `*` port `443` TCP. Simulate traffic
   on port 443 and confirm it is blocked.
7. Sentinel: send traffic on port 23 (Telnet) — the rule-based IDS fires.
8. Sentinel: tick "Failed login?" and send five packets — a rule-based IDS alert appears.
9. Sentinel → IDS dashboard: send five low-volume packets from one source, then a
   high-volume spike from the same source — the anomaly IDS trips when the volume
   exceeds mean + 3σ.

## API quick reference

| Route | Method | Purpose |
|---|---|---|
| `/api/health` | GET | Status and student details |
| `/api/auth/register` | POST | Register, generate RSA key + X.509 cert |
| `/api/auth/login` | POST | Authenticate |
| `/api/keys/directory` | GET | Public key directory |
| `/api/keys/certificate/<username>` | GET | Download X.509 certificate |
| `/api/rsa` | POST | Encrypt/decrypt/sign/verify |
| `/api/hash` | POST | SHA-512 |
| `/api/dh` | GET | Diffie-Hellman example |
| `/api/elgamal/sign` | POST | ElGamal signature |
| `/api/elgamal/verify` | POST | Verify signature |
| `/api/tunnel/start` | POST | Start TLS/SSH handshake |
| `/api/tunnel/next` | POST | Step forward |
| `/api/ipsec` | GET | Packet structure definitions |
| `/api/firewall` | GET/POST | View/add rules |
| `/api/firewall/<id>` | PUT/DELETE | Edit/delete rule |
| `/api/traffic` | POST | Simulate packet, run firewall + IDS |
| `/api/ids/dashboard` | GET | Alerts, packets, baselines |
| `/api/threats` | GET | Threat encyclopedia |

## Important limitations

This is an **academic simulator**. No real network packets are captured, filtered or
transmitted. The firewall does not modify OS firewall settings. The TLS/SSH visualizers
represent protocol sequencing, not actual TLS or SSH transports. Diffie-Hellman and
ElGamal intentionally use tiny illustrative parameters — never use for real
cryptographic protection. Self-signed X.509 certificates are not browser-trusted; the
project does not implement a real CA or authenticated PKI. Login is demonstrational and
lacks production hardening (rate limiting, session persistence, CSRF protection). Never
enter real credentials or private keys.

## Do not commit

`node_modules/`, `.venv/`, `cryptoshield.sqlite3`, or any real private keys.

## Screenshots

Real captures from the running application are in `screenshots/`.

| File | Module | What it shows |
|---|---|---|
| `01-dashboard.png` | Overview | Dashboard with project overview and demo checklist |
| `02-cryptovault-account.png` | CryptoVault | Account & keys tab (registration form) |
| `03-cryptovault-register.png` | CryptoVault | Registration result with generated RSA private/public keys and X.509 download button |
| `04-cryptovault-rsa-encrypt.png` | CryptoVault | RSA-OAEP encryption of a message with the public key |
| `05-cryptovault-rsa-decrypt.png` | CryptoVault | RSA-OAEP decryption recovering the plaintext |
| `06-cryptovault-dh.png` | CryptoVault | Diffie-Hellman exchange — Alice and Bob derive the same shared secret |
| `07-cryptovault-elgamal.png` | CryptoVault | ElGamal signature created and verified |
| `08-securetunnel-tls.png` | SecureTunnel | TLS 1.3 handshake timeline (all five steps) + IPsec packet structure |
| `09-securetunnel-ssh.png` | SecureTunnel | SSH handshake timeline (all six steps) |
| `10-securetunnel-ipsec.png` | SecureTunnel | IPsec ESP diagram in tunnel mode |
| `11-sentinel-firewall.png` | Sentinel | Firewall rule manager with rules list |
| `12-sentinel-traffic-blocked.png` | Sentinel | Port-443 packet blocked by the newly added BLOCK rule |
| `13-sentinel-traffic-alerts.png` | Sentinel | Telnet rule-IDS alert, failed-login alert, and anomaly alert |
| `14-sentinel-ids-dashboard.png` | Sentinel | IDS dashboard — Recharts volume time-series, alert feed, packet table |
| `15-sentinel-threats.png` | Sentinel | Threat encyclopedia entries |

## License

Academic coursework for Koneru Lakshmaiah Education Foundation (KL University).
