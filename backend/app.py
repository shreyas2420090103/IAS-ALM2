"""CryptoShield: cybersecurity learning suite. Classroom demos only, not production security."""
import base64
import hashlib
import ipaddress
import json
import math
import secrets
import sqlite3
import statistics
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Lock

from flask import Flask, jsonify, request
from flask_cors import CORS
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).parent
DB_PATH = ROOT / "cryptoshield.sqlite3"
app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": ["http://localhost:5173", "http://127.0.0.1:5173"]}})
db_lock = Lock()
sessions = {}
handshakes = {}
traffic_history = defaultdict(lambda: deque(maxlen=40))
failed_logins = defaultdict(deque)


def connect_db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with connect_db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                public_pem TEXT NOT NULL,
                cert_pem TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS firewall (
                id INTEGER PRIMARY KEY,
                source TEXT NOT NULL DEFAULT '*',
                destination TEXT NOT NULL DEFAULT '*',
                port TEXT NOT NULL DEFAULT '*',
                protocol TEXT NOT NULL DEFAULT '*',
                action TEXT NOT NULL CHECK(action IN ('ALLOW','BLOCK'))
            );
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY,
                created TEXT NOT NULL,
                kind TEXT NOT NULL,
                severity TEXT NOT NULL,
                detail TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY,
                created TEXT NOT NULL,
                source TEXT NOT NULL,
                destination TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                action TEXT NOT NULL
            );
            """
        )
        if not conn.execute("SELECT 1 FROM firewall LIMIT 1").fetchone():
            conn.executemany(
                "INSERT INTO firewall(source,destination,port,protocol,action) VALUES(?,?,?,?,?)",
                [("*", "*", "23", "TCP", "BLOCK"), ("*", "*", "22", "TCP", "ALLOW")],
            )


def get_body():
    return request.get_json(silent=True) or {}


def fail(msg, code=400):
    return jsonify(error=msg), code


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def key_to_pub_pem(key):
    return (
        key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )


def key_to_priv_pem(key):
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


def build_self_signed_cert(username, key):
    """Demo PKI: self-signed, NOT issued by a trusted CA."""
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, username)])
    dt = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt - timedelta(minutes=1))
        .not_valid_after(dt + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


@app.errorhandler(Exception)
def handle_error(ex):
    if isinstance(ex, sqlite3.IntegrityError):
        return fail("Username already taken", 409)
    if isinstance(ex, ValueError):
        return fail(str(ex))
    app.logger.exception("Request failed")
    return fail("Request failed. Check inputs and backend logs.", 500)


# ---------------------------------------------------------------- Health
@app.get("/api/health")
def health():
    return jsonify(
        status="ok",
        project="CryptoShield",
        student="T Shreyas Reddy",
        roll="YOUR_ROLL_NUMBER",
        department="CSE",
    )


# --------------------------------------------------- CryptoVault: Auth
@app.post("/api/auth/register")
def register():
    d = get_body()
    username = str(d.get("username", "")).strip()
    password = str(d.get("password", ""))
    if not (3 <= len(username) <= 40 and username.replace("_", "").isalnum()):
        return fail("Username must be 3-40 alphanumeric/underscore characters")
    if len(password) < 8:
        return fail("Password must be at least 8 characters")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 250000).hex()
    cert = build_self_signed_cert(username, key)
    with connect_db() as conn:
        conn.execute(
            "INSERT INTO users(username,password_hash,salt,public_pem,cert_pem) VALUES(?,?,?,?,?)",
            (username, digest, salt, key_to_pub_pem(key), cert),
        )
    return (
        jsonify(
            message="Registered. Copy your private key now; it is not stored on the server.",
            private_key=key_to_priv_pem(key),
            public_key=key_to_pub_pem(key),
            certificate=cert,
        ),
        201,
    )


@app.post("/api/auth/login")
def login():
    d = get_body()
    with connect_db() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username=?", (d.get("username", ""),)
        ).fetchone()
    if not row:
        return fail("Invalid login", 401)
    digest = hashlib.pbkdf2_hmac(
        "sha256", str(d.get("password", "")).encode(), bytes.fromhex(row["salt"]), 250000
    ).hex()
    if not secrets.compare_digest(digest, row["password_hash"]):
        return fail("Invalid login", 401)
    token = secrets.token_urlsafe(32)
    sessions[token] = row["username"]
    return jsonify(
        token=token,
        username=row["username"],
        public_key=row["public_pem"],
        certificate=row["cert_pem"],
    )


@app.get("/api/keys/directory")
def public_key_directory():
    with connect_db() as conn:
        rows = conn.execute("SELECT username, public_pem FROM users ORDER BY username").fetchall()
    return jsonify(users=[dict(r) for r in rows])


@app.get("/api/keys/certificate/<username>")
def download_certificate(username):
    with connect_db() as conn:
        row = conn.execute("SELECT cert_pem FROM users WHERE username=?", (username,)).fetchone()
    if not row:
        return fail("Certificate not found", 404)
    return app.response_class(
        row["cert_pem"],
        mimetype="application/x-pem-file",
        headers={"Content-Disposition": f'attachment; filename="{username}.crt"'},
    )


# ------------------------------------------------- CryptoVault: RSA
@app.post("/api/rsa")
def rsa_operations():
    d = get_body()
    op = d.get("operation")
    message = str(d.get("message", ""))
    try:
        if op in ("encrypt", "verify"):
            key = serialization.load_pem_public_key(str(d["key"]).encode())
            if not isinstance(key, rsa.RSAPublicKey):
                return fail("Expected an RSA public key")
        elif op in ("decrypt", "sign"):
            key = serialization.load_pem_private_key(str(d["key"]).encode(), password=None)
            if not isinstance(key, rsa.RSAPrivateKey):
                return fail("Expected an RSA private key")
        else:
            return fail("Operation must be encrypt, decrypt, sign or verify")

        if op == "encrypt":
            output = base64.b64encode(
                key.encrypt(
                    message.encode(),
                    padding.OAEP(
                        mgf=padding.MGF1(hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None,
                    ),
                )
            ).decode()
        elif op == "decrypt":
            output = key.decrypt(
                base64.b64decode(message, validate=True),
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            ).decode()
        elif op == "sign":
            output = base64.b64encode(
                key.sign(
                    message.encode(),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )
            ).decode()
        else:  # verify
            key.verify(
                base64.b64decode(str(d.get("signature", "")), validate=True),
                message.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            output = "Signature verified successfully."
        return jsonify(result=output)
    except Exception:
        return fail("Cryptographic operation failed. Check your key, message and signature.")


# ------------------------------------------------ CryptoVault: SHA-512
@app.post("/api/hash")
def sha512_hash():
    return jsonify(sha512=hashlib.sha512(str(get_body().get("message", "")).encode()).hexdigest())


# --------------------------------------------- CryptoVault: Diffie-Hellman
# Illustrative small parameters. Never use for real key exchange.
DH_PRIME, DH_GENERATOR = 7919, 7


@app.get("/api/dh")
def diffie_hellman_demo():
    a = secrets.randbelow(DH_PRIME - 3) + 2
    b = secrets.randbelow(DH_PRIME - 3) + 2
    A = pow(DH_GENERATOR, a, DH_PRIME)
    B = pow(DH_GENERATOR, b, DH_PRIME)
    return jsonify(
        p=DH_PRIME,
        g=DH_GENERATOR,
        a=a,
        b=b,
        A=A,
        B=B,
        alice_secret=pow(B, a, DH_PRIME),
        bob_secret=pow(A, b, DH_PRIME),
        note="Educational parameters only; not cryptographically secure.",
    )


# ------------------------------------------ CryptoVault: ElGamal + SHA-512
EL_PRIME, EL_GENERATOR = 7919, 7


@app.post("/api/elgamal/sign")
def elgamal_sign():
    message = str(get_body().get("message", ""))
    x = secrets.randbelow(EL_PRIME - 3) + 2
    y = pow(EL_GENERATOR, x, EL_PRIME)
    h = int(hashlib.sha512(message.encode()).hexdigest(), 16) % (EL_PRIME - 1)
    k = secrets.randbelow(EL_PRIME - 2) + 1
    while math.gcd(k, EL_PRIME - 1) != 1:
        k = secrets.randbelow(EL_PRIME - 2) + 1
    r = pow(EL_GENERATOR, k, EL_PRIME)
    s = ((h - x * r) * pow(k, -1, EL_PRIME - 1)) % (EL_PRIME - 1)
    return jsonify(
        hash=hashlib.sha512(message.encode()).hexdigest(),
        p=EL_PRIME,
        g=EL_GENERATOR,
        public_key=y,
        private_key=x,
        r=r,
        s=s,
        warning="Illustrative ElGamal only. Not suitable for real signatures.",
    )


@app.post("/api/elgamal/verify")
def elgamal_verify():
    d = get_body()
    try:
        p, g, y, r, s = [int(d[k]) for k in ("p", "g", "public_key", "r", "s")]
        if p != EL_PRIME or g != EL_GENERATOR:
            return fail("Signature parameters do not match this demo")
        if not (1 <= r < p and 0 <= s < p - 1 and 1 <= y < p):
            return fail("Invalid signature parameters")
        h = int(hashlib.sha512(str(d.get("message", "")).encode()).hexdigest(), 16) % (p - 1)
        left = pow(g, h, p)
        right = (pow(y, r, p) * pow(r, s, p)) % p
        return jsonify(valid=left == right, left=left, right=right)
    except (KeyError, TypeError, ValueError):
        return fail("Invalid verification input")


# ------------------------------------------------ SecureTunnel: TLS/SSH
TLS_STEPS = [
    (
        "Client Hello",
        "Client → Server",
        "Client proposes TLS versions, cipher suites and its ephemeral key share.",
    ),
    (
        "Server Hello",
        "Server → Client",
        "Server selects TLS 1.3 parameters and returns its own ephemeral key share.",
    ),
    (
        "Certificate & Authentication",
        "Server → Client",
        "Server presents its certificate chain and proves possession of the private key.",
    ),
    (
        "Shared Traffic Keys",
        "Both",
        "Both endpoints derive traffic keys from the authenticated (EC)DHE exchange and transcript via HKDF.",
    ),
    (
        "Finished & Encrypted Channel",
        "Both",
        "Finished messages authenticate the transcript; application data then uses AEAD encryption.",
    ),
]

SSH_STEPS = [
    (
        "Version Exchange",
        "Both",
        "Client and server exchange SSH protocol version strings.",
    ),
    (
        "Algorithm Negotiation",
        "Both",
        "Key-exchange, host-key, cipher and MAC/AEAD algorithms are negotiated.",
    ),
    (
        "Key Exchange",
        "Both",
        "Ephemeral Diffie-Hellman produces a shared secret over the untrusted network.",
    ),
    (
        "Server Host Authentication",
        "Server → Client",
        "Server signs the exchange with its host key; the client matches it against known hosts.",
    ),
    (
        "User Authentication",
        "Client → Server",
        "The user authenticates with a public key or (simulated) password.",
    ),
    (
        "Encrypted Session",
        "Both",
        "An authenticated, encrypted SSH session is now active.",
    ),
]


@app.post("/api/tunnel/start")
def start_handshake():
    protocol = str(get_body().get("protocol", "TLS")).upper()
    if protocol not in ("TLS", "SSH"):
        return fail("Protocol must be TLS or SSH")
    sid = secrets.token_urlsafe(18)
    with db_lock:
        handshakes[sid] = {"protocol": protocol, "index": -1}
    steps = TLS_STEPS if protocol == "TLS" else SSH_STEPS
    return jsonify(session_id=sid, protocol=protocol, total=len(steps))


@app.post("/api/tunnel/next")
def advance_handshake():
    sid = get_body().get("session_id")
    with db_lock:
        state = handshakes.get(sid)
        if not state:
            return fail("Session not found; start a new handshake", 404)
        steps = TLS_STEPS if state["protocol"] == "TLS" else SSH_STEPS
        state["index"] += 1
        idx = state["index"]
        if idx >= len(steps):
            return jsonify(done=True, index=len(steps), total=len(steps))
        title, direction, detail = steps[idx]
    return jsonify(
        done=idx == len(steps) - 1,
        index=idx + 1,
        total=len(steps),
        title=title,
        direction=direction,
        detail=detail,
        protocol=state["protocol"],
    )


@app.get("/api/ipsec")
def ipsec_modes():
    return jsonify(
        modes={
            "transport": {
                "parts": [
                    {"label": "Original IP Header", "protected": False},
                    {"label": "ESP Header", "protected": False},
                    {"label": "TCP/UDP + Data", "protected": True},
                    {"label": "ESP Trailer", "protected": True},
                    {"label": "Authentication Tag", "protected": False},
                ],
                "description": "Transport mode protects the payload; the original IP header stays visible.",
            },
            "tunnel": {
                "parts": [
                    {"label": "New IP Header", "protected": False},
                    {"label": "ESP Header", "protected": False},
                    {"label": "Original IP Header", "protected": True},
                    {"label": "TCP/UDP + Data", "protected": True},
                    {"label": "ESP Trailer", "protected": True},
                    {"label": "Authentication Tag", "protected": False},
                ],
                "description": "Tunnel mode wraps and encrypts the whole original packet inside a new outer header.",
            },
        }
    )


# ------------------------------------------------------ Sentinel: Firewall
def ip_matches(rule, incoming):
    if rule == "*":
        return True
    try:
        return ipaddress.ip_address(incoming) in ipaddress.ip_network(rule, strict=False)
    except ValueError:
        return False


def raise_alert(conn, kind, severity, detail):
    conn.execute(
        "INSERT INTO alerts(created,kind,severity,detail) VALUES(?,?,?,?)",
        (utc_now(), kind, severity, detail),
    )


@app.route("/api/firewall", methods=["GET", "POST"])
def firewall_rules():
    if request.method == "GET":
        with connect_db() as conn:
            rows = conn.execute("SELECT * FROM firewall ORDER BY id DESC").fetchall()
        return jsonify(rules=[dict(r) for r in rows])

    d = get_body()
    source, destination, port, protocol, action = (
        str(d.get(k, "*")).strip() for k in ("source", "destination", "port", "protocol", "action")
    )
    protocol, action = protocol.upper(), action.upper()
    for address in (source, destination):
        if address != "*":
            try:
                ipaddress.ip_network(address, strict=False)
            except ValueError:
                return fail("Source/destination must be an IP, CIDR or *")
    if port != "*" and (not port.isdigit() or not 0 <= int(port) <= 65535):
        return fail("Port must be 0-65535 or *")
    if protocol not in ("*", "TCP", "UDP", "ICMP") or action not in ("ALLOW", "BLOCK"):
        return fail("Invalid protocol or action")
    with connect_db() as conn:
        cur = conn.execute(
            "INSERT INTO firewall(source,destination,port,protocol,action) VALUES(?,?,?,?,?)",
            (source, destination, port, protocol, action),
        )
    return jsonify(id=cur.lastrowid), 201


@app.route("/api/firewall/<int:rule_id>", methods=["PUT", "DELETE"])
def update_delete_rule(rule_id):
    with connect_db() as conn:
        if request.method == "DELETE":
            conn.execute("DELETE FROM firewall WHERE id=?", (rule_id,))
        else:
            d = get_body()
            row = conn.execute("SELECT * FROM firewall WHERE id=?", (rule_id,)).fetchone()
            if not row:
                return fail("Rule not found", 404)
            vals = {
                k: (
                    str(d.get(k, row[k])).strip().upper()
                    if k in ("protocol", "action")
                    else str(d.get(k, row[k])).strip()
                )
                for k in ("source", "destination", "port", "protocol", "action")
            }
            for address in (vals["source"], vals["destination"]):
                if address != "*":
                    try:
                        ipaddress.ip_network(address, strict=False)
                    except ValueError:
                        return fail("Invalid address or CIDR")
            if vals["port"] != "*" and (
                not vals["port"].isdigit() or not 0 <= int(vals["port"]) <= 65535
            ):
                return fail("Invalid port")
            if vals["protocol"] not in ("*", "TCP", "UDP", "ICMP") or vals["action"] not in (
                "ALLOW",
                "BLOCK",
            ):
                return fail("Invalid protocol or action")
            conn.execute(
                "UPDATE firewall SET source=?,destination=?,port=?,protocol=?,action=? WHERE id=?",
                (*vals.values(), rule_id),
            )
    return jsonify(ok=True)


# ------------------------------------------------------ Sentinel: IDS
@app.post("/api/traffic")
def simulate_traffic():
    d = get_body()
    source = str(d.get("source", "192.168.1.100"))
    destination = str(d.get("destination", "10.0.0.10"))
    try:
        ipaddress.ip_address(source)
        ipaddress.ip_address(destination)
    except ValueError:
        return fail("Provide valid IPv4 or IPv6 addresses")
    try:
        port = int(d.get("port", 80))
        volume = int(d.get("volume", 1))
    except (ValueError, TypeError):
        return fail("Port and volume must be numbers")
    if not 0 <= port <= 65535 or not 1 <= volume <= 500:
        return fail("Port must be 0-65535; volume 1-500")
    protocol = str(d.get("protocol", "TCP")).upper()
    if protocol not in ("TCP", "UDP", "ICMP"):
        return fail("Invalid protocol")

    with connect_db() as conn:
        rules = conn.execute("SELECT * FROM firewall ORDER BY id DESC").fetchall()
        matched = next(
            (
                r
                for r in rules
                if ip_matches(r["source"], source)
                and ip_matches(r["destination"], destination)
                and (r["port"] == "*" or r["port"] == str(port))
                and r["protocol"] in ("*", protocol)
            ),
            None,
        )
        action = matched["action"] if matched else "ALLOW"
        conn.execute(
            "INSERT INTO packets(created,source,destination,port,protocol,action) VALUES(?,?,?,?,?,?)",
            (utc_now(), source, destination, port, protocol, action),
        )
        triggered = []
        if action == "BLOCK":
            triggered.append(
                ("Firewall", "medium", f"{source} → {destination}:{port} blocked by rule #{matched['id']}")
            )
        if port == 23:
            triggered.append(("Rule IDS", "high", f"Telnet traffic detected from {source}"))
        if d.get("failed_login"):
            attempts = failed_logins[source]
            t = datetime.now(timezone.utc)
            while attempts and (t - attempts[0]).total_seconds() > 60:
                attempts.popleft()
            attempts.append(t)
            if len(attempts) >= 5:
                triggered.append(
                    ("Rule IDS", "high", f"{len(attempts)} failed SSH logins in 60s from {source}")
                )
        history = traffic_history[source]
        if len(history) >= 5:
            mean = statistics.mean(history)
            sd = statistics.pstdev(history)
            if volume > mean + 3 * max(sd, 1):
                triggered.append(
                    (
                        "Anomaly IDS",
                        "critical",
                        f"Volume {volume} deviates from baseline {mean:.1f} + 3σ ({sd:.1f}) at {source}",
                    )
                )
        history.append(volume)
        for kind, sev, msg in triggered:
            raise_alert(conn, kind, sev, msg)
    return jsonify(
        action=action,
        alerts=[{"kind": k, "severity": s, "detail": m} for k, s, m in triggered],
        volume=volume,
        baseline=list(history),
    )


@app.get("/api/ids/dashboard")
def ids_dashboard():
    with connect_db() as conn:
        alerts = [dict(r) for r in conn.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 40")]
        packets = [dict(r) for r in conn.execute("SELECT * FROM packets ORDER BY id DESC LIMIT 30")]
    return jsonify(
        alerts=alerts,
        packets=packets,
        baselines={k: list(v) for k, v in traffic_history.items()},
    )


@app.get("/api/threats")
def threat_encyclopedia():
    return jsonify(
        items=[
            {
                "name": "File Infector Virus",
                "type": "Virus",
                "description": "Injects malicious code into executables so it runs whenever the host file runs.",
                "defense": "Code signing, endpoint protection, least privilege, offline backups.",
            },
            {
                "name": "Boot Sector Virus",
                "type": "Virus",
                "description": "Overwrites the boot record to execute during system startup.",
                "defense": "Secure Boot, verified recovery media, full-disk scanning.",
            },
            {
                "name": "Email Worm",
                "type": "Worm",
                "description": "Self-replicates through malicious email attachments and links.",
                "defense": "Attachment filtering, patching, macro restrictions, user training.",
            },
            {
                "name": "Network Worm",
                "type": "Worm",
                "description": "Spreads autonomously by exploiting vulnerable network services.",
                "defense": "Patch management, network segmentation, egress filtering, IDS.",
            },
            {
                "name": "Bastion Host",
                "type": "Firewall Architecture",
                "description": "A hardened, exposed gateway that mediates access to a protected network.",
                "defense": "MFA, tightly restricted management access, extensive logging, minimal services.",
            },
        ]
    )


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=False)
else:
    init_db()
