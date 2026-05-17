package gui

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/Yunushan/ssl-certificate-verifier/internal/checker"
)

// Server hosts the browser-based GUI and API.
type Server struct {
	Defaults checker.Options
}

// New returns a GUI server with default check options.
func New(defaults checker.Options) *Server {
	return &Server{Defaults: defaults}
}

// Handler returns an HTTP handler for the GUI.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.index)
	mux.HandleFunc("/api/check", s.checkAPI)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	return secureHeaders(mux)
}

type checkRequest struct {
	Target         string `json:"target"`
	Port           int    `json:"port"`
	ServerName     string `json:"server_name"`
	VerifyName     string `json:"verify_name"`
	TimeoutSeconds int    `json:"timeout_seconds"`
	TLSMin         string `json:"tls_min"`
	TLSMax         string `json:"tls_max"`
	CAFile         string `json:"ca_file"`
	NoHostname     bool   `json:"no_hostname"`
	IncludePEM     bool   `json:"include_pem"`
	SkipTLSProbe   bool   `json:"skip_tls_probe"`
	ForceTLS       bool   `json:"force_tls"`
}

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(indexHTML))
}

func (s *Server) checkAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()
	var req checkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if strings.TrimSpace(req.Target) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "target is required"})
		return
	}

	opt := s.Defaults
	opt.Port = req.Port
	opt.ServerName = strings.TrimSpace(req.ServerName)
	opt.VerifyName = strings.TrimSpace(req.VerifyName)
	opt.TLSMin = strings.TrimSpace(req.TLSMin)
	opt.TLSMax = strings.TrimSpace(req.TLSMax)
	opt.CAFile = strings.TrimSpace(req.CAFile)
	opt.NoHostname = req.NoHostname
	opt.IncludePEM = req.IncludePEM
	opt.SkipTLSProbe = req.SkipTLSProbe
	opt.ForceTLS = req.ForceTLS
	if req.TimeoutSeconds > 0 {
		opt.Timeout = time.Duration(req.TimeoutSeconds) * time.Second
	}

	ctx, cancel := context.WithTimeout(r.Context(), opt.Timeout+2*time.Second)
	defer cancel()
	result, err := checker.Check(ctx, req.Target, opt)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

const indexHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>SSL Certificate Verifier</title>
  <style>
    :root { color-scheme: dark; --bg:#0d1117; --panel:#161b22; --panel2:#0f1722; --border:#30363d; --text:#e6edf3; --muted:#8b949e; --accent:#58a6ff; --good:#3fb950; --bad:#f85149; --warn:#d29922; }
    * { box-sizing:border-box; }
    body { margin:0; font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; background:var(--bg); color:var(--text); }
    header { max-width:1100px; margin:0 auto; padding:32px 20px 18px; text-align:center; }
    h1 { margin:8px 0 10px; font-size:clamp(30px, 5vw, 46px); letter-spacing:-0.03em; }
    .subtitle { max-width:900px; margin:0 auto 16px; font-weight:700; line-height:1.55; }
    .badges { display:flex; flex-wrap:wrap; justify-content:center; gap:7px; margin:18px auto; }
    .badge { display:inline-flex; overflow:hidden; border-radius:5px; font-size:12px; font-weight:700; line-height:1; border:1px solid rgba(255,255,255,.08); }
    .badge span { padding:5px 7px; background:#30363d; }
    .badge b { padding:5px 7px; background:#238636; }
    .badge.blue b { background:#0969da; } .badge.orange b { background:#bc4c00; } .badge.gray b { background:#57606a; }
    nav { margin-top:12px; color:var(--muted); } nav a { color:var(--accent); text-decoration:none; margin:0 4px; } nav a:hover { text-decoration:underline; }
    main { max-width:1100px; margin:0 auto; padding:0 20px 36px; }
    .rule { height:4px; background:var(--border); margin:12px 0 26px; }
    .panel { background:var(--panel); border:1px solid var(--border); border-radius:12px; padding:18px; margin-bottom:16px; box-shadow:0 10px 28px rgba(0,0,0,.22); }
    .grid { display:grid; grid-template-columns:repeat(12, 1fr); gap:12px; }
    .col-12 { grid-column:span 12; } .col-8 { grid-column:span 8; } .col-6 { grid-column:span 6; } .col-4 { grid-column:span 4; } .col-3 { grid-column:span 3; }
    label { display:block; font-size:13px; font-weight:700; color:var(--muted); margin-bottom:5px; }
    input, select { width:100%; background:#0d1117; color:var(--text); border:1px solid var(--border); border-radius:8px; padding:10px 11px; font:inherit; }
    input[type="checkbox"] { width:auto; margin-right:8px; }
    .checkrow { display:flex; gap:14px; flex-wrap:wrap; align-items:center; margin-top:8px; color:var(--muted); }
    .checkrow label { margin:0; color:var(--text); display:flex; align-items:center; font-weight:600; }
    button { background:#238636; border:1px solid rgba(255,255,255,.08); color:white; font-weight:800; padding:11px 16px; border-radius:8px; cursor:pointer; }
    button:hover { filter:brightness(1.1); }
    button:disabled { opacity:.65; cursor:wait; }
    .muted { color:var(--muted); }
    .cards { display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin-top:14px; }
    .card { background:var(--panel2); border:1px solid var(--border); border-radius:10px; padding:13px; }
    .card .k { color:var(--muted); font-size:12px; font-weight:800; text-transform:uppercase; letter-spacing:.06em; }
    .card .v { margin-top:7px; font-size:18px; font-weight:800; word-break:break-word; }
    .ok { color:var(--good); } .bad { color:var(--bad); } .warn { color:var(--warn); }
    table { width:100%; border-collapse:collapse; margin-top:10px; }
    th, td { text-align:left; border-bottom:1px solid var(--border); padding:9px; vertical-align:top; }
    th { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.06em; }
    pre { background:#0d1117; border:1px solid var(--border); border-radius:10px; overflow:auto; padding:14px; line-height:1.45; }
    details { margin-top:12px; }
    summary { cursor:pointer; color:var(--accent); font-weight:800; }
    .errorbox { border-color:rgba(248,81,73,.45); background:rgba(248,81,73,.08); }
    @media (max-width:800px) { .col-8,.col-6,.col-4,.col-3 { grid-column:span 12; } .cards { grid-template-columns:1fr; } header { text-align:left; } .badges { justify-content:flex-start; } }
  </style>
</head>
<body>
<header>
  <h1>SSL Certificate Verifier</h1>
  <p class="subtitle">Operator-first TLS/SSL certificate checking workspace with domain, IP, HTTP/HTTPS, non-standard port, TLS version, root, intermediate and chain verification support.</p>
  <div class="badges">
    <span class="badge"><span>build</span><b>ready</b></span>
    <span class="badge blue"><span>release</span><b>v0.1.0</b></span>
    <span class="badge blue"><span>license</span><b>MIT</b></span>
    <span class="badge orange"><span>runtime</span><b>Go</b></span>
    <span class="badge gray"><span>targets</span><b>domain · IP · URL</b></span>
    <span class="badge blue"><span>interfaces</span><b>CLI · GUI</b></span>
  </div>
  <nav><a href="#check">Check</a> • <a href="#results">Results</a> • <a href="/healthz">Health</a></nav>
</header>
<main>
  <div class="rule"></div>
  <section id="check" class="panel">
    <div class="grid">
      <div class="col-8"><label for="target">Target</label><input id="target" placeholder="example.com, 10.0.0.5:8443, https://intranet.local:9443, http://router.local:8080" value="example.com" /></div>
      <div class="col-4"><label for="port">Override port</label><input id="port" type="number" min="1" max="65535" placeholder="optional" /></div>
      <div class="col-4"><label for="servername">SNI server name</label><input id="servername" placeholder="optional, e.g. app.internal" /></div>
      <div class="col-4"><label for="verifyname">Hostname verify name</label><input id="verifyname" placeholder="optional, defaults to SNI/host" /></div>
      <div class="col-4"><label for="timeout">Timeout seconds</label><input id="timeout" type="number" min="1" max="120" value="10" /></div>
      <div class="col-3"><label for="tlsmin">TLS min</label><select id="tlsmin"><option value="">auto</option><option>1.0</option><option>1.1</option><option>1.2</option><option>1.3</option></select></div>
      <div class="col-3"><label for="tlsmax">TLS max</label><select id="tlsmax"><option value="">auto</option><option>1.0</option><option>1.1</option><option>1.2</option><option>1.3</option></select></div>
      <div class="col-6"><label for="cafile">Custom CA file on this machine</label><input id="cafile" placeholder="optional path to PEM bundle" /></div>
      <div class="col-12 checkrow">
        <label><input id="force" type="checkbox" /> Force TLS even for http://</label>
        <label><input id="nohost" type="checkbox" /> Skip hostname verification</label>
        <label><input id="skipprobe" type="checkbox" /> Skip TLS version probe</label>
        <label><input id="pem" type="checkbox" /> Include PEM in JSON</label>
      </div>
      <div class="col-12"><button id="run">Run certificate check</button> <span class="muted" id="hint">The check runs from this host, so private networks are supported when reachable from here.</span></div>
    </div>
  </section>
  <section id="results" class="panel"><p class="muted">Run a check to view TLS, certificate chain, root trust and hostname verification results.</p></section>
</main>
<script>
const $ = (id) => document.getElementById(id);
const esc = (v) => String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const yes = (v) => v ? '<span class="ok">PASS</span>' : '<span class="bad">FAIL</span>';
const yn = (v) => v ? '<span class="ok">yes</span>' : '<span class="bad">no</span>';

$('run').addEventListener('click', async () => {
  const payload = {
    target: $('target').value,
    port: Number($('port').value || 0),
    server_name: $('servername').value,
    verify_name: $('verifyname').value,
    timeout_seconds: Number($('timeout').value || 10),
    tls_min: $('tlsmin').value,
    tls_max: $('tlsmax').value,
    ca_file: $('cafile').value,
    force_tls: $('force').checked,
    no_hostname: $('nohost').checked,
    skip_tls_probe: $('skipprobe').checked,
    include_pem: $('pem').checked
  };
  $('run').disabled = true;
  $('results').innerHTML = '<p class="muted">Checking…</p>';
  try {
    const res = await fetch('/api/check', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload)});
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'check failed');
    render(data);
  } catch (err) {
    $('results').innerHTML = '<div class="panel errorbox"><strong class="bad">Error</strong><p>' + esc(err.message) + '</p></div>';
  } finally {
    $('run').disabled = false;
  }
});

function render(r) {
  const certs = r.certificates || [];
  const versions = (r.tls && r.tls.supported_versions) || [];
  const warnings = r.warnings || [];
  const errors = [...(r.errors || []), ...((r.verification && r.verification.errors) || [])];
  let html = '';
  html += '<h2>Result for ' + esc(r.target.host) + ':' + esc(r.target.port) + '</h2>';
  html += '<div class="cards">';
  html += card('Protocol', r.protocol || '-');
  html += card('TLS connected', r.tls && r.tls.attempted ? (r.tls.connected ? '<span class="ok">yes</span>' : '<span class="bad">no</span>') : '-');
  html += card('Certificate', r.verification && r.verification.checked ? yes(r.verification.verified) : '<span class="warn">not checked</span>');
  html += card('Hostname', r.verification && r.verification.hostname_checked ? yes(r.verification.hostname_verified) : '<span class="warn">skipped</span>');
  html += '</div>';
  html += '<table><tbody>';
  html += row('Address', r.target.address);
  html += row('SNI', r.target.server_name || '<none>');
  html += row('Verify name', r.target.verify_name || '<none>');
  html += row('Negotiated TLS', (r.tls && r.tls.negotiated_version) || '-');
  html += row('Cipher suite', (r.tls && r.tls.cipher_suite) || '-');
  html += row('ALPN', (r.tls && r.tls.alpn) || '-');
  html += row('Root trusted', r.verification && r.verification.checked ? yn(r.verification.root_trusted) : '-');
  html += row('Chain complete', r.verification && r.verification.checked ? yn(r.verification.chain_complete) : '-');
  html += '</tbody></table>';
  if (r.http && r.http.attempted) {
    html += '<h3>HTTP</h3><table><tbody>' + row('URL', r.http.url) + row('Reachable', r.http.reachable ? 'yes' : 'no') + row('Status', r.http.status || '-') + row('Server', r.http.server || '-') + '</tbody></table>';
  }
  if (versions.length) {
    html += '<h3>TLS version support</h3><table><thead><tr><th>Version</th><th>Supported</th><th>Cipher / Error</th></tr></thead><tbody>';
    versions.forEach(v => html += '<tr><td>' + esc(v.version) + '</td><td>' + (v.supported ? '<span class="ok">yes</span>' : '<span class="bad">no</span>') + '</td><td>' + esc(v.cipher_suite || v.error || '-') + '</td></tr>');
    html += '</tbody></table>';
  }
  if (certs.length) {
    html += '<h3>Server-sent certificates</h3><table><thead><tr><th>#</th><th>Role</th><th>Subject</th><th>Issuer</th><th>Valid until</th><th>SHA-256</th></tr></thead><tbody>';
    certs.forEach(c => html += '<tr><td>' + c.index + '</td><td>' + esc(c.role) + '</td><td>' + esc(c.subject_common_name || c.subject) + '</td><td>' + esc(c.issuer_common_name || c.issuer) + '</td><td>' + esc(c.not_after) + '</td><td><code>' + esc(c.fingerprint_sha256) + '</code></td></tr>');
    html += '</tbody></table>';
  }
  if (warnings.length) html += '<h3 class="warn">Warnings</h3><ul>' + warnings.map(w => '<li>' + esc(w) + '</li>').join('') + '</ul>';
  if (errors.length) html += '<h3 class="bad">Errors</h3><ul>' + errors.map(e => '<li>' + esc(e) + '</li>').join('') + '</ul>';
  html += '<details><summary>Raw JSON report</summary><pre>' + esc(JSON.stringify(r, null, 2)) + '</pre></details>';
  $('results').innerHTML = html;
}
function card(k, v) { return '<div class="card"><div class="k">' + esc(k) + '</div><div class="v">' + v + '</div></div>'; }
function row(k, v) { return '<tr><th>' + esc(k) + '</th><td>' + esc(v) + '</td></tr>'; }
</script>
</body>
</html>`
