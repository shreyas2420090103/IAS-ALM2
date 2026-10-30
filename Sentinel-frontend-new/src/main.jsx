import axios from "axios";
import { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import {
  Activity,
  AlertTriangle,
  Binary,
  Copy,
  Download,
  FileLock2,
  FlaskConical,
  Globe,
  Key,
  Lock,
  Plus,
  RefreshCw,
  Router,
  Send,
  Shield,
  ShieldCheck,
  Trash2,
  UserPlus,
  Zap,
} from "lucide-react";
import "./style.css";

const api = axios.create({ baseURL: "/api" });

/* ------------------------------- helpers ------------------------------- */
const Card = ({ title, icon, children, className = "" }) => (
  <section className={`card ${className}`}>
    <h3 className="card-title">
      {icon}
      <span>{title}</span>
    </h3>
    <div className="card-body">{children}</div>
  </section>
);

const Field = ({ label, children }) => (
  <label className="field">
    <span className="field-label">{label}</span>
    {children}
  </label>
);

const Btn = ({ onClick, disabled, children, tone = "primary", ...rest }) => (
  <button
    className={`btn btn-${tone}`}
    onClick={onClick}
    disabled={disabled}
    type="button"
    {...rest}
  >
    {children}
  </button>
);

const Mono = ({ children, rows = 4 }) => {
  const text = children ?? "";
  const lineCount = Math.max(rows, text.split("\n").length + 1);
  return <textarea className="mono" rows={lineCount} value={text} readOnly />;
};

const Tag = ({ kind }) => {
  const map = {
    high: "tag-high",
    medium: "tag-medium",
    critical: "tag-critical",
    low: "tag-low",
    Pass: "tag-ok",
    ALLOW: "tag-ok",
    BLOCK: "tag-block",
  };
  return <span className={`tag ${map[kind] ?? "tag-low"}`}>{kind}</span>;
};

/* ------------------------------ navigation ----------------------------- */
const TABS = [
  { id: "home", label: "Dashboard", icon: <Globe size={16} /> },
  { id: "vault", label: "CryptoVault", icon: <Key size={16} /> },
  { id: "tunnel", label: "SecureTunnel", icon: <Lock size={16} /> },
  { id: "sentinel", label: "Sentinel", icon: <Shield size={16} /> },
];

/* --------------------------------- home -------------------------------- */
function Home() {
  const [health, setHealth] = useState(null);
  useEffect(() => {
    api.get("/health").then((r) => setHealth(r.data)).catch(() => {});
  }, []);
  return (
    <div className="grid two-col">
      <Card title="Project overview" icon={<Activity size={18} />}>
        <p className="lead">
          <strong>CryptoShield</strong> is an interactive cybersecurity learning suite that bundles
          three academic modules covering public-key cryptography, transport-layer security and
          intrusion detection.
        </p>
        <ul className="feature-list">
          <li><Key size={15} /> CryptoVault — RSA, Diffie-Hellman, ElGamal signatures, SHA-512, X.509 certificates.</li>
          <li><Lock size={15} /> SecureTunnel — TLS 1.3 and SSH handshake visualizers plus IPsec modes.</li>
          <li><Shield size={15} /> Sentinel — firewall rule engine, rule-based IDS and statistical anomaly detection.</li>
        </ul>
        {health && (
          <div className="meta-row">
            <span>Student</span><strong>{health.student}</strong>
            <span>Roll</span><strong>{health.roll}</strong>
            <span>Dept</span><strong>{health.department}</strong>
          </div>
        )}
      </Card>
      <Card title="Quick demo checklist" icon={<FlaskConical size={18} />}>
        <ol className="demo-steps">
          <li>Register a demo account in CryptoVault; copy the private key when shown.</li>
          <li>Encrypt a short message with your public key, then decrypt it with the private key.</li>
          <li>Sign a message, then verify the signature — tamper with the text and re-verify.</li>
          <li>Walk through the Diffie-Hellman exchange and confirm both secrets match.</li>
          <li>Run the TLS and SSH handshake timelines in SecureTunnel.</li>
          <li>Add a BLOCK rule for TCP/443 in Sentinel, then simulate port-443 traffic.</li>
          <li>Trigger failed SSH logins five times and watch the IDS alert feed.</li>
          <li>Send five low-volume packets from one IP, then a spike, to trip anomaly detection.</li>
        </ol>
      </Card>
    </div>
  );
}

/* ------------------------------ CryptoVault ----------------------------- */
function CryptoVault() {
  const [tab, setTab] = useState("account");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [result, setResult] = useState(null);
  const [directory, setDirectory] = useState([]);
  const [rsaOp, setRsaOp] = useState("encrypt");
  const [rsaKey, setRsaKey] = useState("");
  const [rsaMsg, setRsaMsg] = useState("");
  const [rsaOut, setRsaOut] = useState(null);
  const [hashText, setHashText] = useState("");
  const [hashOut, setHashOut] = useState("");
  const [dh, setDh] = useState(null);
  const [egMsg, setEgMsg] = useState("");
  const [egSig, setEgSig] = useState(null);
  const [egVerify, setEgVerify] = useState(null);

  const refreshDirectory = () =>
    api.get("/keys/directory").then((r) => setDirectory(r.data.users)).catch(() => {});

  useEffect(() => {
    if (tab === "directory") refreshDirectory();
  }, [tab]);

  const doRegister = async () => {
    try {
      const r = await api.post("/auth/register", { username, password });
      setResult(r.data);
    } catch (e) {
      setResult({ error: e.response?.data?.error ?? "Registration failed" });
    }
  };

  const doLogin = async () => {
    try {
      const r = await api.post("/auth/login", { username, password });
      setResult(r.data);
    } catch (e) {
      setResult({ error: e.response?.data?.error ?? "Login failed" });
    }
  };

  const doRsa = async () => {
    try {
      const r = await api.post("/rsa", {
        operation: rsaOp,
        key: rsaKey,
        message: rsaMsg,
      });
      setRsaOut(r.data.result);
    } catch (e) {
      setRsaOut(e.response?.data?.error ?? "RSA operation failed");
    }
  };

  const doHash = async () => {
    const r = await api.post("/hash", { message: hashText });
    setHashOut(r.data.sha512);
  };

  const doDh = async () => {
    const r = await api.get("/dh");
    setDh(r.data);
  };

  const doElgamal = async () => {
    const r = await api.post("/elgamal/sign", { message: egMsg });
    setEgSig(r.data);
    setEgVerify(null);
  };

  const doVerify = async () => {
    if (!egSig) return;
    const r = await api.post("/elgamal/verify", {
      message: egMsg,
      p: egSig.p,
      g: egSig.g,
      public_key: egSig.public_key,
      r: egSig.r,
      s: egSig.s,
    });
    setEgVerify(r.data);
  };

  const tamperAndVerify = async () => {
    if (!egSig) return;
    const r = await api.post("/elgamal/verify", {
      message: egMsg + " (tampered)",
      p: egSig.p,
      g: egSig.g,
      public_key: egSig.public_key,
      r: egSig.r,
      s: egSig.s,
    });
    setEgVerify(r.data);
  };

  const downloadCert = (user) =>
    window.open(`/api/keys/certificate/${user}`, "_blank");

  return (
    <div className="stack">
      <div className="tab-row">
        {[
          ["account", "Account & keys"],
          ["rsa", "RSA"],
          ["hash", "SHA-512"],
          ["dh", "Diffie-Hellman"],
          ["elgamal", "ElGamal"],
          ["directory", "Directory"],
        ].map(([id, label]) => (
          <Btn key={id} tone={tab === id ? "primary" : "ghost"} onClick={() => setTab(id)}>
            {label}
          </Btn>
        ))}
      </div>

      {tab === "account" && (
        <div className="grid two-col">
          <Card title="Register / login" icon={<UserPlus size={18} />}>
            <Field label="Username">
              <input value={username} onChange={(e) => setUsername(e.target.value)} />
            </Field>
            <Field label="Password (min 8 chars)">
              <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
            </Field>
            <div className="btn-row">
              <Btn onClick={doRegister}><UserPlus size={15} /> Register</Btn>
              <Btn onClick={doLogin} tone="ghost"><Send size={15} /> Login</Btn>
            </div>
          </Card>
          <Card title="Result" icon={<FileLock2 size={18} />}>
            {!result && <p className="muted">No action yet.</p>}
            {result?.error && <p className="error">{result.error}</p>}
            {result?.private_key && (
              <>
                <p className="warn">
                  Copy this private key now — it is never stored by the server.
                </p>
                <Mono rows={9}>{result.private_key}</Mono>
              </>
            )}
            {result?.public_key && <Mono rows={5}>{result.public_key}</Mono>}
            {result?.certificate && (
              <Btn onClick={() => downloadCert(username)} tone="ghost">
                <Download size={15} /> Download X.509 certificate
              </Btn>
            )}
            {result?.token && <p className="ok">Logged in as {result.username}.</p>}
          </Card>
        </div>
      )}

      {tab === "rsa" && (
        <Card title="RSA-OAEP / RSA-PSS" icon={<Binary size={18} />}>
          <div className="grid three-col">
            <Field label="Operation">
              <select value={rsaOp} onChange={(e) => setRsaOp(e.target.value)}>
                <option value="encrypt">Encrypt (public key)</option>
                <option value="decrypt">Decrypt (private key)</option>
                <option value="sign">Sign (private key)</option>
                <option value="verify">Verify (public key)</option>
              </select>
            </Field>
            <Field label="Message / ciphertext / signature">
              <input value={rsaMsg} onChange={(e) => setRsaMsg(e.target.value)} />
            </Field>
            <Field label="PEM key">
              <input value={rsaKey} onChange={(e) => setRsaKey(e.target.value)} placeholder="Paste key" />
            </Field>
          </div>
          <Btn onClick={doRsa}><Send size={15} /> Run operation</Btn>
          {rsaOut != null && <Mono rows={4}>{rsaOut}</Mono>}
        </Card>
      )}

      {tab === "hash" && (
        <Card title="SHA-512" icon={<Copy size={18} />}>
          <Field label="Message">
            <textarea rows={3} value={hashText} onChange={(e) => setHashText(e.target.value)} />
          </Field>
          <Btn onClick={doHash}><Zap size={15} /> Hash</Btn>
          {hashOut && <Mono rows={3}>{hashOut}</Mono>}
        </Card>
      )}

      {tab === "dh" && (
        <Card title="Diffie-Hellman key exchange" icon={<Router size={18} />}>
          <Btn onClick={doDh}><RefreshCw size={15} /> New exchange</Btn>
          {dh && (
            <div className="grid three-col">
              <div className="dh-panel">
                <h4>Alice</h4>
                <p>private a = {dh.a}</p>
                <p>public A = g^a mod p = {dh.A}</p>
                <p className="ok">secret = {dh.alice_secret}</p>
              </div>
              <div className="dh-panel">
                <h4>Public parameters</h4>
                <p>prime p = {dh.p}</p>
                <p>generator g = {dh.g}</p>
                <p className="muted">{dh.note}</p>
              </div>
              <div className="dh-panel">
                <h4>Bob</h4>
                <p>private b = {dh.b}</p>
                <p>public B = g^b mod p = {dh.B}</p>
                <p className="ok">secret = {dh.bob_secret}</p>
              </div>
            </div>
          )}
        </Card>
      )}

      {tab === "elgamal" && (
        <Card title="ElGamal signature + SHA-512" icon={<FileLock2 size={18} />}>
          <Field label="Message to sign">
            <textarea rows={2} value={egMsg} onChange={(e) => setEgMsg(e.target.value)} />
          </Field>
          <div className="btn-row">
            <Btn onClick={doElgamal}><Send size={15} /> Sign</Btn>
            <Btn onClick={doVerify} tone="ghost" disabled={!egSig}><ShieldCheck size={15} /> Verify</Btn>
            <Btn onClick={tamperAndVerify} tone="danger" disabled={!egSig}>
              <AlertTriangle size={15} /> Tamper & verify
            </Btn>
          </div>
          {egSig && (
            <div className="meta-row">
              <span>r</span><strong>{egSig.r}</strong>
              <span>s</span><strong>{egSig.s}</strong>
              <span>y</span><strong>{egSig.public_key}</strong>
            </div>
          )}
          {egVerify && (
            <p className={egVerify.valid ? "ok" : "error"}>
              {egVerify.valid ? "Signature VALID (left = right)" : "Signature INVALID — message was modified"}
            </p>
          )}
          {egSig?.hash && <Mono rows={2}>{egSig.hash}</Mono>}
        </Card>
      )}

      {tab === "directory" && (
        <Card title="Public key directory" icon={<Globe size={18} />}>
          <Btn onClick={refreshDirectory} tone="ghost"><RefreshCw size={15} /> Refresh</Btn>
          {directory.length === 0 && <p className="muted">No registered users yet.</p>}
          <ul className="dir-list">
            {directory.map((u) => (
              <li key={u.username}>
                <span>{u.username}</span>
                <div className="btn-row">
                  <Btn onClick={() => downloadCert(u.username)} tone="ghost">
                    <Download size={14} /> cert
                  </Btn>
                </div>
              </li>
            ))}
          </ul>
        </Card>
      )}
    </div>
  );
}

/* ----------------------------- SecureTunnel ----------------------------- */
function SecureTunnel() {
  const [protocol, setProtocol] = useState("TLS");
  const [session, setSession] = useState(null);
  const [log, setLog] = useState([]);
  const [ipsecMode, setIpsecMode] = useState("transport");
  const [ipsec, setIpsec] = useState(null);

  useEffect(() => {
    api.get("/ipsec").then((r) => setIpsec(r.data.modes)).catch(() => {});
  }, []);

  const start = async () => {
    const r = await api.post("/tunnel/start", { protocol });
    setSession(r.data);
    setLog([]);
  };

  const next = async () => {
    if (!session) return;
    const r = await api.post("/tunnel/next", { session_id: session.session_id });
    if (!r.data.done) {
      setLog((l) => [...l, r.data]);
    } else {
      setLog((l) => [...l, { title: "Handshake complete", direction: "—", detail: "Channel is now secure." }]);
    }
  };

  return (
    <div className="stack">
      <Card title="Handshake visualizer" icon={<Lock size={18} />}>
        <div className="btn-row">
          {["TLS", "SSH"].map((p) => (
            <Btn key={p} tone={protocol === p ? "primary" : "ghost"} onClick={() => setProtocol(p)}>
              {p}
            </Btn>
          ))}
          <Btn onClick={start}><Send size={15} /> Start handshake</Btn>
          <Btn onClick={next} tone="ghost" disabled={!session}>
            <Activity size={15} /> Next step
          </Btn>
        </div>
        <div className="log-panel">
          {log.length === 0 && <p className="muted">Click “Start handshake”, then “Next step” repeatedly.</p>}
          {log.map((entry, i) => (
            <div key={i} className="log-entry">
              <span className="log-step">{i + 1}</span>
              <span className="log-title">{entry.title}</span>
              <span className="log-dir">{entry.direction}</span>
              <p>{entry.detail}</p>
            </div>
          ))}
        </div>
      </Card>

      <Card title="IPsec ESP packet structure" icon={<Router size={18} />}>
        <div className="btn-row">
          {["transport", "tunnel"].map((m) => (
            <Btn key={m} tone={ipsecMode === m ? "primary" : "ghost"} onClick={() => setIpsecMode(m)}>
              {m} mode
            </Btn>
          ))}
        </div>
        {ipsec && (
          <>
            <div className="packet-strip">
              {ipsec[ipsecMode].parts.map((part, i) => (
                <div
                  key={i}
                  className={`packet-part ${part.protected ? "packet-protected" : "packet-clear"}`}
                >
                  {part.label}
                </div>
              ))}
            </div>
            <p className="muted">{ipsec[ipsecMode].description}</p>
          </>
        )}
      </Card>
    </div>
  );
}

/* -------------------------------- Sentinel ------------------------------ */
function Sentinel() {
  const [tab, setTab] = useState("firewall");
  const [rules, setRules] = useState([]);
  const [newRule, setNewRule] = useState({
    source: "*",
    destination: "*",
    port: "*",
    protocol: "*",
    action: "BLOCK",
  });
  const [traffic, setTraffic] = useState({
    source: "192.168.1.100",
    destination: "10.0.0.10",
    port: 80,
    protocol: "TCP",
    volume: 1,
    failed_login: false,
  });
  const [lastResult, setLastResult] = useState(null);
  const [dashboard, setDashboard] = useState(null);
  const [threats, setThreats] = useState([]);

  const loadRules = () =>
    api.get("/firewall").then((r) => setRules(r.data.rules)).catch(() => {});
  const loadDashboard = () =>
    api.get("/ids/dashboard").then((r) => setDashboard(r.data)).catch(() => {});

  useEffect(() => {
    loadRules();
    loadDashboard();
    api.get("/threats").then((r) => setThreats(r.data.items)).catch(() => {});
  }, []);

  const addRule = async () => {
    await api.post("/firewall", newRule);
    loadRules();
  };

  const deleteRule = async (id) => {
    await api.delete(`/firewall/${id}`);
    loadRules();
  };

  const sendTraffic = async () => {
    const r = await api.post("/traffic", traffic);
    setLastResult(r.data);
    loadDashboard();
  };

  const chartData = useMemo(() => {
    if (!dashboard) return [];
    const rows = [];
    const baselines = dashboard.baselines;
    for (const [ip, samples] of Object.entries(baselines)) {
      samples.forEach((v, i) => rows.push({ ip, sample: i + 1, volume: v }));
    }
    return rows;
  }, [dashboard]);

  return (
    <div className="stack">
      <div className="tab-row">
        {[
          ["firewall", "Firewall"],
          ["ids", "IDS dashboard"],
          ["encyclopedia", "Threats"],
        ].map(([id, label]) => (
          <Btn key={id} tone={tab === id ? "primary" : "ghost"} onClick={() => setTab(id)}>
            {label}
          </Btn>
        ))}
      </div>

      {tab === "firewall" && (
        <div className="stack">
          <Card title="Add rule" icon={<Plus size={18} />}>
            <div className="grid five-col">
              <Field label="Source"><input value={newRule.source} onChange={(e) => setNewRule({ ...newRule, source: e.target.value })} /></Field>
              <Field label="Destination"><input value={newRule.destination} onChange={(e) => setNewRule({ ...newRule, destination: e.target.value })} /></Field>
              <Field label="Port"><input value={newRule.port} onChange={(e) => setNewRule({ ...newRule, port: e.target.value })} /></Field>
              <Field label="Protocol">
                <select value={newRule.protocol} onChange={(e) => setNewRule({ ...newRule, protocol: e.target.value })}>
                  <option value="*">any</option><option value="TCP">TCP</option>
                  <option value="UDP">UDP</option><option value="ICMP">ICMP</option>
                </select>
              </Field>
              <Field label="Action">
                <select value={newRule.action} onChange={(e) => setNewRule({ ...newRule, action: e.target.value })}>
                  <option value="ALLOW">ALLOW</option><option value="BLOCK">BLOCK</option>
                </select>
              </Field>
            </div>
            <Btn onClick={addRule}><Plus size={15} /> Add</Btn>
          </Card>
          <Card title="Rules" icon={<Shield size={18} />}>
            {rules.length === 0 && <p className="muted">No rules configured.</p>}
            <ul className="rule-list">
              {rules.map((r) => (
                <li key={r.id}>
                  <code>#{r.id}</code>
                  <span>{r.source}</span> → <span>{r.destination}</span>
                  <span>: {r.port}/{r.protocol}</span>
                  <Tag kind={r.action} />
                  <Btn onClick={() => deleteRule(r.id)} tone="danger"><Trash2 size={14} /></Btn>
                </li>
              ))}
            </ul>
          </Card>
          <Card title="Simulate traffic" icon={<Send size={18} />}>
            <div className="grid four-col">
              <Field label="Source"><input value={traffic.source} onChange={(e) => setTraffic({ ...traffic, source: e.target.value })} /></Field>
              <Field label="Destination"><input value={traffic.destination} onChange={(e) => setTraffic({ ...traffic, destination: e.target.value })} /></Field>
              <Field label="Port"><input value={traffic.port} onChange={(e) => setTraffic({ ...traffic, port: +e.target.value })} /></Field>
              <Field label="Protocol">
                <select value={traffic.protocol} onChange={(e) => setTraffic({ ...traffic, protocol: e.target.value })}>
                  <option>TCP</option><option>UDP</option><option>ICMP</option>
                </select>
              </Field>
              <Field label="Volume (1-500)"><input value={traffic.volume} onChange={(e) => setTraffic({ ...traffic, volume: +e.target.value })} /></Field>
              <Field label="Failed login?">
                <input type="checkbox" checked={traffic.failed_login} onChange={(e) => setTraffic({ ...traffic, failed_login: e.target.checked })} />
              </Field>
            </div>
            <Btn onClick={sendTraffic}><Send size={15} /> Send packet</Btn>
            {lastResult && (
              <div className="result-row">
                <Tag kind={lastResult.action} />
                <p>
                  {lastResult.action === "BLOCK" ? "Packet was blocked by the firewall." : "Packet was allowed."}
                  {lastResult.alerts.length > 0 && " IDS raised alerts."}
                </p>
              </div>
            )}
          </Card>
        </div>
      )}

      {tab === "ids" && dashboard && (
        <div className="stack">
          <div className="btn-row">
            <Btn onClick={loadDashboard} tone="ghost"><RefreshCw size={15} /> Refresh</Btn>
          </div>
          <Card title="Anomaly detection — traffic volume over time" icon={<Activity size={18} />}>
            {chartData.length === 0 ? (
              <p className="muted">Send traffic from the Firewall tab to build a baseline.</p>
            ) : (
              <ResponsiveContainer width="100%" height={220}>
                <AreaChart data={chartData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="sample" />
                  <YAxis />
                  <Tooltip />
                  <Area type="monotone" dataKey="volume" stroke="#6ee7b7" fill="#6ee7b733" />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </Card>
          <Card title="Recent alerts" icon={<AlertTriangle size={18} />}>
            {dashboard.alerts.length === 0 && <p className="muted">No alerts yet.</p>}
            <ul className="alert-list">
              {dashboard.alerts.map((a) => (
                <li key={a.id}>
                  <Tag kind={a.severity} />
                  <span>{a.kind}</span>
                  <p>{a.detail}</p>
                  <span className="muted">{a.created}</span>
                </li>
              ))}
            </ul>
          </Card>
          <Card title="Recent packets" icon={<Router size={18} />}>
            <table className="packet-table">
              <thead>
                <tr><th>Time</th><th>Source</th><th>Destination</th><th>Port</th><th>Proto</th><th>Action</th></tr>
              </thead>
              <tbody>
                {dashboard.packets.map((p) => (
                  <tr key={p.id}>
                    <td>{p.created}</td><td>{p.source}</td><td>{p.destination}</td>
                    <td>{p.port}</td><td>{p.protocol}</td>
                    <td><Tag kind={p.action} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>
        </div>
      )}

      {tab === "encyclopedia" && (
        <Card title="Threat encyclopedia" icon={<AlertTriangle size={18} />}>
          {threats.map((t) => (
            <article key={t.name} className="threat-item">
              <h4>{t.name}</h4>
              <p className="muted">{t.type}</p>
              <p>{t.description}</p>
              <p className="ok"><strong>Defense:</strong> {t.defense}</p>
            </article>
          ))}
        </Card>
      )}
    </div>
  );
}

/* --------------------------------- app --------------------------------- */
function App() {
  const [tab, setTab] = useState("home");
  return (
    <div className="app-shell">
      <header className="app-header">
        <h1>
          <Shield size={26} /> CryptoShield
        </h1>
        <p className="subtitle">Cybersecurity learning suite — T Shreyas Reddy (YOUR_ROLL_NUMBER)</p>
        <nav className="nav">
          {TABS.map((t) => (
            <Btn key={t.id} tone={tab === t.id ? "primary" : "ghost"} onClick={() => setTab(t.id)}>
              {t.icon} {t.label}
            </Btn>
          ))}
        </nav>
      </header>
      <main className="content">
        {tab === "home" && <Home />}
        {tab === "vault" && <CryptoVault />}
        {tab === "tunnel" && <SecureTunnel />}
        {tab === "sentinel" && <Sentinel />}
      </main>
      <footer className="app-footer">
        <p>Academic simulation only. Never submit real credentials or private keys.</p>
      </footer>
    </div>
  );
}

createRoot(document.getElementById("root")).render(<App />);
