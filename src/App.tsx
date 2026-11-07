import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  ArrowDownToLine, ArrowUpFromLine, ChevronDown, ChevronRight,
  Computer, Folder, FolderPlus, HardDrive, Home, ListFilter,
  MoreHorizontal, Network, Plus, RefreshCw, Search, Settings,
  ShieldCheck, Upload, Download, Wifi, X,
} from "lucide-react";

type AppInfo = { name: string; version: string; status: string };

const localFiles = [
  { name: "Documents", kind: "folder", size: "—", modified: "Today" },
  { name: "Downloads", kind: "folder", size: "—", modified: "Today" },
  { name: "Projects", kind: "folder", size: "—", modified: "Yesterday" },
  { name: "archive.tar.zst", kind: "file", size: "2.4 GiB", modified: "Nov 6, 2026" },
  { name: "disk-image.E01", kind: "file", size: "48.2 GiB", modified: "Nov 4, 2026" },
  { name: "notes.txt", kind: "file", size: "12 KiB", modified: "Nov 2, 2026" },
];

function App() {
  const [info, setInfo] = useState<AppInfo | null>(null);
  const [showConnect, setShowConnect] = useState(false);
  const [host, setHost] = useState("");
  const [username, setUsername] = useState("");
  const [authMethod, setAuthMethod] = useState("password");

  useEffect(() => {
    invoke<AppInfo>("get_app_info").then(setInfo).catch(() => undefined);
  }, []);

  return (
    <main className="app-shell">
      <header className="topbar">
        <div className="brand"><div className="brand-mark"><Network size={18} /></div><span>Rust<span className="brand-light">SFTP</span></span></div>
        <div className="topbar-center"><span className="connection-indicator" /> No active connection</div>
        <div className="topbar-actions">
          <button className="icon-button" title="Settings"><Settings size={17} /></button>
          <button className="avatar">N</button>
        </div>
      </header>

      <section className="toolbar">
        <div className="toolbar-group">
          <button className="primary-button" onClick={() => setShowConnect(true)}><Plus size={16} /> New connection</button>
          <button className="tool-button" disabled><RefreshCw size={15} /> Reconnect</button>
        </div>
        <div className="toolbar-divider" />
        <div className="toolbar-group">
          <button className="tool-button" disabled><ArrowUpFromLine size={15} /> Upload</button>
          <button className="tool-button" disabled><ArrowDownToLine size={15} /> Download</button>
        </div>
        <div className="toolbar-spacer" />
        <div className="secure-label"><ShieldCheck size={14} /> SSH encrypted</div>
      </section>

      <section className="workspace">
        <aside className="sidebar">
          <div className="sidebar-label">CONNECTIONS</div>
          <button className="sidebar-item active"><Network size={16} /> Sites <span className="sidebar-count">0</span></button>
          <button className="sidebar-item" onClick={() => setShowConnect(true)}><Plus size={16} /> Add connection</button>
          <div className="sidebar-label sidebar-label-spaced">LOCAL</div>
          <button className="sidebar-item"><Home size={16} /> Home</button>
          <button className="sidebar-item"><Download size={16} /> Downloads</button>
          <button className="sidebar-item"><Computer size={16} /> Filesystem</button>
          <div className="sidebar-bottom"><div className="sidebar-label">TRANSFER QUEUE</div><div className="queue-empty"><ArrowDownToLine size={18} /><span>No active transfers</span></div></div>
        </aside>

        <div className="main-panel">
          <div className="welcome">
            <div className="welcome-icon"><Network size={25} /></div>
            <h1>Connect to a server</h1>
            <p>Your files, wherever they live. Connect to an SFTP server to get started.</p>
            <button className="primary-button welcome-button" onClick={() => setShowConnect(true)}><Plus size={16} /> New connection</button>
          </div>
          <div className="pane-grid">
            <section className="file-pane">
              <div className="pane-header"><div className="pane-title"><HardDrive size={15} /> Local site</div><span className="pane-status">LOCAL</span></div>
              <div className="pathbar"><button className="path-home"><Home size={14} /></button><span>/home/you</span><div className="path-actions"><button className="icon-button"><Search size={14} /></button><button className="icon-button"><ListFilter size={14} /></button></div></div>
              <div className="file-header"><span>Name</span><span>Size</span><span>Modified</span></div>
              <div className="file-list">{localFiles.map((file) => <div className="file-row" key={file.name}><span className="file-name">{file.kind === "folder" ? <Folder size={16} /> : <div className="file-dot" />} {file.name}</span><span>{file.size}</span><span>{file.modified}</span></div>)}</div>
              <div className="pane-footer">Local filesystem · Demo preview</div>
            </section>
            <section className="file-pane remote-pane">
              <div className="pane-header"><div className="pane-title"><Network size={15} /> Remote site</div><span className="pane-status disconnected">DISCONNECTED</span></div>
              <div className="pathbar"><button className="path-home" disabled><Home size={14} /></button><span className="muted">No remote directory</span></div>
              <div className="remote-empty"><div className="remote-empty-icon"><Wifi size={22} /></div><strong>Not connected</strong><span>Connect to an SFTP server to browse remote files.</span><button className="text-button" onClick={() => setShowConnect(true)}>Connect to server <ChevronRight size={14} /></button></div>
              <div className="pane-footer">SFTP · Awaiting connection</div>
            </section>
          </div>
        </div>
      </section>

      <footer className="statusbar"><span><span className="status-dot" /> Ready</span><span>{info ? `v${info.version} · ${info.status}` : "Initializing…"}</span></footer>

      {showConnect && <div className="modal-backdrop" onMouseDown={(e) => { if (e.target === e.currentTarget) setShowConnect(false); }}>
        <section className="connect-modal">
          <div className="modal-heading"><div><span className="eyebrow">NEW CONNECTION</span><h2>Connect to a server</h2></div><button className="icon-button" onClick={() => setShowConnect(false)}><X size={18} /></button></div>
          <label>Host <input autoFocus placeholder="sftp.example.com" value={host} onChange={(e) => setHost(e.target.value)} /></label>
          <div className="form-row"><label>Port <input defaultValue="22" /></label><label>Username <input placeholder="username" value={username} onChange={(e) => setUsername(e.target.value)} /></label></div>
          <label>Authentication
            <select value={authMethod} onChange={(e) => setAuthMethod(e.target.value)}>
              <option value="password">Password</option><option value="key">Private key</option><option value="agent">SSH agent</option>
            </select>
          </label>
          {authMethod === "password" && <label>Password <input type="password" placeholder="Password" /></label>}
          {authMethod === "key" && <label>Private key file <input placeholder="Select an OpenSSH private key…" /></label>}
          <div className="hostkey-note"><ShieldCheck size={16} /><span>Host key verification will be required before credentials are sent.</span></div>
          <div className="modal-actions"><button className="tool-button" onClick={() => setShowConnect(false)}>Cancel</button><button className="primary-button" disabled title="Connection workflow is not implemented yet">Connect <ChevronRight size={15} /></button></div>
          <p className="modal-footnote">Connection is a UI scaffold; SSH authentication is not wired up yet.</p>
        </section>
      </div>}
    </main>
  );
}

export default App;
