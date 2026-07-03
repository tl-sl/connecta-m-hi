'use strict';
const http = require('http');
const fs = require('fs');
const crypto = require('crypto');
const net = require('net');
const os = require('os');
const { execSync } = require('child_process');

const PORT = 7890;
const CONFIG_PATH = '/opt/oticonnect/config.json';
const LINK_BASE = 'https://dom.oti.cat/api/ha/link';
const POLL_BASE = 'https://dom.oti.cat/api/ha/link';

const CREDENTIALS_URL = 'https://dom.oti.cat/api/ha/credentials';
const REVOKE_URL = 'https://dom.oti.cat/api/ha/link/revoke';

const MOSQUITTO_CONF = '/etc/mosquitto/mosquitto.conf';
const MOSQUITTO_CONF_D = '/etc/mosquitto/conf.d';
const BRIDGE_CONF = '/etc/mosquitto/conf.d/oti-bridge.conf';
const BRIDGE_PASSWD = '/etc/mosquitto/conf.d/oti-passwd';
const Z2M_CONFIG = '/opt/zigbee2mqtt/data/configuration.yaml';

const INTEGRATIONS = [
  { key: 'zigbee2mqtt', label: 'Zigbee2MQTT' },
  { key: 'mosquitto', label: 'Mosquitto bridge' },
  { key: 'vpn', label: 'LAN proxy' },
];

// --- Device identity ---
function getDeviceId() {
  try {
    return fs.readFileSync('/sys/class/net/eth0/address', 'utf8').trim();
  } catch {
    return 'unknown';
  }
}

function getLocalIp() {
  try {
    var ifaces = os.networkInterfaces();
    var candidates = ifaces['eth0'] || ifaces['br-lan'] || [];
    var ipv4 = candidates.find(function(a) { return a.family === 'IPv4' && !a.internal; });
    return ipv4 ? ipv4.address : null;
  } catch { return null; }
}

function getLanSubnet() {
  try {
    var ifaces = os.networkInterfaces();
    var candidates = ifaces['eth0'] || ifaces['br-lan'] || [];
    var ipv4 = candidates.find(function(a) { return a.family === 'IPv4' && !a.internal; });
    if (!ipv4 || !ipv4.cidr) return null;
    var parts = ipv4.cidr.split('/');
    var prefix = parseInt(parts[1]);
    var a = parts[0].split('.').map(Number);
    var mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
    var net = ((a[0]<<24 | a[1]<<16 | a[2]<<8 | a[3]) & mask) >>> 0;
    return [(net>>>24)&0xFF,(net>>>16)&0xFF,(net>>>8)&0xFF,net&0xFF].join('.') + '/' + prefix;
  } catch { return null; }
}

// --- Config persistence ---
function loadConfig() {
  try {
    return JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
  } catch {
    return {};
  }
}

function saveConfig(cfg) {
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(cfg, null, 2));
}

function ensureState(cfg) {
  if (!cfg.state) {
    cfg.state = crypto.randomBytes(8).toString('hex');
    saveConfig(cfg);
  }
  return cfg.state;
}

function ensureIntegrations(cfg) {
  if (!cfg.integrations) {
    cfg.integrations = { zigbee2mqtt: 'pending', mosquitto: 'pending', vpn: 'pending' };
  }
  return cfg.integrations;
}

// --- Credential fetching ---
function fetchCredentials() {
  var cfg = loadConfig();
  if (!cfg.token) return Promise.resolve();
  return fetch(CREDENTIALS_URL, { headers: { 'Authorization': 'Bearer ' + cfg.token } })
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (!data.mqtt_user) {
        process.stdout.write('credentials error: ' + JSON.stringify(data) + '\n');
        return;
      }
      var c = loadConfig();
      c.credentials = {
        instance_id: data.instance_id,
        mqtt_user: data.mqtt_user,
        mqtt_password: data.mqtt_password,
        mqtt_host: data.mqtt_host,
      };
      saveConfig(c);
      process.stdout.write('credentials fetched for instance ' + data.instance_id + '\n');
    })
    .catch(function(e) {
      process.stdout.write('credentials fetch failed: ' + e.message + '\n');
    });
}

// Tell dom.oti.cat to revoke this device's link server-side so the long-lived JWT can no longer
// fetch MQTT credentials. Best-effort: unlinking must succeed locally even if dom is unreachable.
function revokeToken(cfg) {
  if (!cfg || !cfg.token) return Promise.resolve();
  return fetch(REVOKE_URL, { method: 'POST', headers: { 'Authorization': 'Bearer ' + cfg.token } })
    .then(function(r) { process.stdout.write('token revoke: ' + r.status + '\n'); })
    .catch(function(e) { process.stdout.write('token revoke failed: ' + e.message + '\n'); });
}

// --- Mosquitto bridge ---
// Returns true if it changed anything (and restarted mosquitto), false if already correct.
// Idempotent so reconcileIntegrations() can call it on every boot without bouncing the broker.
function applyMosquitto(cfg) {
  var creds = cfg.credentials;
  if (!creds || !creds.mqtt_user || !creds.mqtt_password || !creds.mqtt_host) {
    throw new Error('credentials not available — wait for credential fetch to complete');
  }
  var clientId = 'tasmota-bridge-' + (cfg.deviceId || 'smhub').replace(/:/g, '');

  var bridgeConf = [
    'listener 1883',
    'allow_anonymous false',
    'password_file ' + BRIDGE_PASSWD,
    '',
    'connection oti-ha',
    'address ' + creds.mqtt_host + ':8883',
    'bridge_cafile /etc/ssl/certs/ca-certificates.crt',
    'remote_username ' + creds.mqtt_user,
    'remote_password ' + creds.mqtt_password,
    'remote_clientid ' + clientId,
    'bridge_protocol_version mqttv311',
    'cleansession false',
    'try_private false',
    'topic tele/# both 0',
    'topic stat/# both 0',
    'topic cmnd/# both 0',
    'topic tasmota/# both 0',
  ].join('\n') + '\n';

  var mainConf = '';
  try { mainConf = fs.readFileSync(MOSQUITTO_CONF, 'utf8'); } catch {}
  var haveInclude = mainConf.includes('include_dir /etc/mosquitto/conf.d');
  var curBridge = '';
  try { curBridge = fs.readFileSync(BRIDGE_CONF, 'utf8'); } catch {}
  var havePasswd = fs.existsSync(BRIDGE_PASSWD);
  // Nothing drifted → no-op (the plaintext remote_password lives in bridgeConf, so a credential
  // change shows up as a bridgeConf diff and still triggers a full re-apply below).
  if (haveInclude && havePasswd && curBridge === bridgeConf) return false;

  try { fs.mkdirSync(MOSQUITTO_CONF_D, { recursive: true }); } catch {}
  if (!haveInclude) {
    fs.appendFileSync(MOSQUITTO_CONF, '\ninclude_dir /etc/mosquitto/conf.d\n');
  }
  execSync(
    'mosquitto_passwd -c -b ' + BRIDGE_PASSWD + ' ' + creds.mqtt_user + ' ' + creds.mqtt_password,
    { timeout: 5000 }
  );
  execSync('chown mosquitto:mosquitto ' + BRIDGE_PASSWD + ' && chmod 640 ' + BRIDGE_PASSWD, { timeout: 3000 });
  fs.writeFileSync(BRIDGE_CONF, bridgeConf);
  execSync('rc-service mosquitto restart', { timeout: 10000 });
  return true;
}

function removeMosquitto() {
  try { fs.unlinkSync(BRIDGE_CONF); } catch {}
  try { fs.unlinkSync(BRIDGE_PASSWD); } catch {}
  execSync('rc-service mosquitto restart', { timeout: 10000 });
}

// --- Zigbee2MQTT ---
function setYamlBlock(yaml, key, block) {
  var lines = yaml.split('\n');
  var result = [];
  var i = 0;
  var found = false;
  var re = new RegExp('^' + key + '(\\s*:.*)$');
  while (i < lines.length) {
    if (!found && re.test(lines[i])) {
      found = true;
      i++;
      while (i < lines.length && /^[ \t]/.test(lines[i])) i++;
      result.push(block);
    } else {
      result.push(lines[i]);
      i++;
    }
  }
  if (!found) {
    if (result.length && result[result.length - 1] !== '') result.push('');
    result.push(block);
  }
  return result.join('\n');
}

function applyZigbee2mqtt(cfg) {
  var creds = cfg.credentials;
  if (!creds || !creds.mqtt_user || !creds.mqtt_password || !creds.mqtt_host) {
    throw new Error('credentials not available — wait for credential fetch to complete');
  }
  var mac = (cfg.deviceId || '000000000000').replace(/:/g, '');
  var clientId = 'z2m_' + mac;
  var baseTopic = 'zigbee2mqtt_' + mac;
  var yaml = '';
  try { yaml = fs.readFileSync(Z2M_CONFIG, 'utf8'); } catch {}
  var mqttBlock = [
    'mqtt:',
    '  base_topic: ' + baseTopic,
    '  server: mqtts://' + creds.mqtt_host + ':8883',
    '  user: ' + creds.mqtt_user,
    '  password: ' + creds.mqtt_password,
    '  client_id: ' + clientId,
    '  ca: /etc/ssl/certs/ca-certificates.crt',
  ].join('\n');
  var haBlock = 'homeassistant:\n  enabled: true';
  var desired = setYamlBlock(setYamlBlock(yaml, 'mqtt', mqttBlock), 'homeassistant', haBlock);
  // Idempotent: only rewrite + restart z2m if the mqtt/homeassistant blocks actually differ, so a
  // reconcile on every boot doesn't drop the Zigbee network when nothing drifted.
  if (desired === yaml) return false;
  fs.writeFileSync(Z2M_CONFIG, desired);
  execSync('rc-service zigbee2mqtt restart', { timeout: 15000 });
  return true;
}

function removeZigbee2mqtt() {
  var yaml = '';
  try { yaml = fs.readFileSync(Z2M_CONFIG, 'utf8'); } catch {}
  yaml = setYamlBlock(yaml, 'mqtt', 'mqtt:\n  server: mqtt://localhost:1883');
  yaml = setYamlBlock(yaml, 'homeassistant', 'homeassistant:\n  enabled: false');
  fs.writeFileSync(Z2M_CONFIG, yaml);
  execSync('rc-service zigbee2mqtt restart', { timeout: 15000 });
}

// --- Self-healing reconcile ---
// The SMHUB regenerates zigbee2mqtt/mosquitto config from its own `configsetting` source of truth
// on OS upgrades, which silently reverts the blocks our integrations wrote (e.g. z2m's mqtt server
// back to localhost, dropping our credentials) and leaves z2m unable to start. Since config.json
// still says the integration is `applied`, we re-assert our config on every boot. apply* are
// idempotent and only restart the affected service when something actually drifted, so this is a
// no-op in the common case. Uses the stored credentials, so it works even if the live credential
// fetch fails (expired token). NOTE: this only heals the config WE own (z2m mqtt/homeassistant
// blocks, mosquitto bridge) — it does NOT touch z2m's serial.adapter, which the SMHUB also resets
// to `zstack` on upgrade; on an EFR32 (ember) hub that still blocks z2m until fixed SMHUB-side.
function reconcileIntegrations() {
  var cfg = loadConfig();
  var ints = cfg.integrations || {};
  if (ints.mosquitto === 'applied') {
    try {
      if (applyMosquitto(cfg)) process.stdout.write('reconcile: re-applied mosquitto (drift healed)\n');
    } catch (e) { process.stdout.write('reconcile mosquitto failed: ' + e.message + '\n'); }
  }
  if (ints.zigbee2mqtt === 'applied') {
    try {
      if (applyZigbee2mqtt(cfg)) process.stdout.write('reconcile: re-applied zigbee2mqtt (drift healed)\n');
    } catch (e) { process.stdout.write('reconcile zigbee2mqtt failed: ' + e.message + '\n'); }
  }
}

// --- LAN proxy + SOCKS5 tunnel ---
// Direction A: HA sidecar → SMHUB (socks5 msgs) → LAN TCP connections
// Direction B: LAN client → SMHUB port 8123 (proxy msgs) → HA instance :8123

var socks5Conns = new Map();  // conn_id → net.Socket (LAN-side TCP for Direction A)
var proxyConns = new Map();   // conn_id → { socket, buf, connected } (Direction B)
var proxyServer = null;

function genConnId() {
  return crypto.randomBytes(6).toString('hex');
}

function handleSocks5Frame(msg) {
  var connId = msg.conn_id;
  if (!connId) return;

  if (msg.event === 'connect') {
    var sock = net.createConnection({ host: msg.host, port: msg.port });
    socks5Conns.set(connId, sock);
    sock.on('connect', function() {
      if (wsConn) wsConn.send(JSON.stringify({ type: 'socks5', conn_id: connId, event: 'connected' }));
    });
    sock.on('data', function(buf) {
      if (wsConn) wsConn.send(JSON.stringify({ type: 'socks5', conn_id: connId, event: 'data', data: buf.toString('base64') }));
    });
    sock.on('close', function() {
      socks5Conns.delete(connId);
      if (wsConn) wsConn.send(JSON.stringify({ type: 'socks5', conn_id: connId, event: 'close' }));
    });
    sock.on('error', function(e) {
      socks5Conns.delete(connId);
      if (wsConn) wsConn.send(JSON.stringify({ type: 'socks5', conn_id: connId, event: 'error', message: e.message }));
    });
    return;
  }

  var sock = socks5Conns.get(connId);
  if (!sock) return;
  if (msg.event === 'data') {
    sock.write(Buffer.from(msg.data, 'base64'));
  } else if (msg.event === 'close' || msg.event === 'error') {
    sock.destroy();
    socks5Conns.delete(connId);
  }
}

function handleProxyFrame(msg) {
  var connId = msg.conn_id;
  if (!connId) return;
  var entry = proxyConns.get(connId);
  if (!entry) return;

  if (msg.event === 'connected') {
    entry.connected = true;
    if (entry.buf.length) {
      var combined = Buffer.concat(entry.buf);
      entry.buf = [];
      if (wsConn) wsConn.send(JSON.stringify({ type: 'proxy', conn_id: connId, event: 'data', data: combined.toString('base64') }));
    }
    return;
  }
  if (msg.event === 'data') {
    entry.socket.write(Buffer.from(msg.data, 'base64'));
  } else if (msg.event === 'close' || msg.event === 'error') {
    entry.socket.destroy();
    proxyConns.delete(connId);
  }
}

function applyVpn() {
  if (proxyServer) return;
  proxyServer = net.createServer(function(sock) {
    if (!wsConn || !wsConnected) { sock.destroy(); return; }
    var connId = genConnId();
    var entry = { socket: sock, buf: [], connected: false };
    proxyConns.set(connId, entry);

    sock.on('data', function(buf) {
      if (!entry.connected) { entry.buf.push(buf); return; }
      if (wsConn) wsConn.send(JSON.stringify({ type: 'proxy', conn_id: connId, event: 'data', data: buf.toString('base64') }));
    });
    sock.on('close', function() {
      proxyConns.delete(connId);
      if (wsConn) wsConn.send(JSON.stringify({ type: 'proxy', conn_id: connId, event: 'close' }));
    });
    sock.on('error', function() { proxyConns.delete(connId); });

    wsConn.send(JSON.stringify({ type: 'proxy', conn_id: connId, event: 'connect', host: 'localhost', port: 8123 }));
  });
  proxyServer.on('error', function(e) {
    process.stdout.write('proxy server error: ' + e.message + '\n');
    proxyServer = null;
  });
  proxyServer.listen(8123, '0.0.0.0', function() {
    process.stdout.write('LAN proxy listening on :8123\n');
    sendSubnet();
  });
}

function removeVpn() {
  if (wsConn && wsConnected) {
    wsConn.send(JSON.stringify({ type: 'subnet', cidr: null }));
  }
  if (proxyServer) { proxyServer.close(); proxyServer = null; }
  proxyConns.forEach(function(e) { e.socket.destroy(); });
  proxyConns.clear();
  socks5Conns.forEach(function(s) { s.destroy(); });
  socks5Conns.clear();
}

function sendSubnet() {
  var cidr = getLanSubnet();
  if (!cidr || !wsConn || !wsConnected) return;
  wsConn.send(JSON.stringify({ type: 'subnet', cidr: cidr }));
  process.stdout.write('sent subnet ' + cidr + '\n');
}

// --- HTML helpers ---
function esc(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

const STYLE = `
<style>
:root {
  --bg: #0f0f0f;
  --card-bg: #161616;
  --card-border: #222;
  --text: #e0e0e0;
  --text-sub: #666;
  --text-dim: #444;
  --text-label: #ccc;
  --badge-bg: #1e1e1e;
  --badge-border: #333;
  --badge-text: #888;
  --divider: #222;
  --row-border: #1e1e1e;
  --modal-bg: #161616;
  --modal-border: #2a2a2a;
  --ghost-border: #333;
  --ghost-text: #888;
  --ghost-hover-border: #555;
  --ghost-hover-text: #aaa;
  --copy-border: #333;
  --copy-text: #666;
  --code-bg: #0f0f0f;
  --code-border: #222;
  --code-text: #aaa;
  --status-pending-bg: #2d1f00;
  --status-pending-text: #f59e0b;
  --status-applied-bg: #052e16;
  --status-applied-text: #22c55e;
  --error-bg: #1a0505;
  --error-border: #7f1d1d;
  --error-text: #ef4444;
  --danger-bg: #7f1d1d;
  --danger-text: #fca5a5;
  --danger-hover-bg: #991b1b;
  --danger-hover-text: #fff;
}
[data-theme="light"] {
  --bg: #f0f2f5;
  --card-bg: #ffffff;
  --card-border: #e2e8f0;
  --text: #1a202c;
  --text-sub: #718096;
  --text-dim: #a0aec0;
  --text-label: #2d3748;
  --badge-bg: #edf2f7;
  --badge-border: #e2e8f0;
  --badge-text: #718096;
  --divider: #e2e8f0;
  --row-border: #edf2f7;
  --modal-bg: #ffffff;
  --modal-border: #e2e8f0;
  --ghost-border: #e2e8f0;
  --ghost-text: #718096;
  --ghost-hover-border: #cbd5e0;
  --ghost-hover-text: #4a5568;
  --copy-border: #e2e8f0;
  --copy-text: #a0aec0;
  --code-bg: #f7fafc;
  --code-border: #e2e8f0;
  --code-text: #4a5568;
  --status-pending-bg: #fffbeb;
  --status-pending-text: #d97706;
  --status-applied-bg: #f0fdf4;
  --status-applied-text: #16a34a;
  --error-bg: #fef2f2;
  --error-border: #fca5a5;
  --error-text: #dc2626;
  --danger-bg: #dc2626;
  --danger-text: #ffffff;
  --danger-hover-bg: #b91c1c;
  --danger-hover-text: #fff;
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: system-ui, -apple-system, sans-serif;
  background: var(--bg);
  color: var(--text);
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 100vh;
  padding: 1rem;
}
.card {
  text-align: center;
  padding: 2.5rem 2rem;
  border: 1px solid var(--card-border);
  border-radius: 12px;
  background: var(--card-bg);
  width: 100%;
  max-width: 420px;
}
.logo { font-size: 1.5rem; font-weight: 700; letter-spacing: -0.5px; }
.logo em { font-style: normal; color: #4a90e2; }
.sub { color: var(--text-sub); font-size: 0.85rem; margin-top: 0.35rem; }
.badge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  margin-top: 1.5rem;
  padding: 0.4rem 1rem;
  background: var(--badge-bg);
  border: 1px solid var(--badge-border);
  border-radius: 999px;
  font-size: 0.8rem;
  color: var(--badge-text);
}
.dot { width: 7px; height: 7px; border-radius: 50%; background: #f59e0b; }
.dot.green { background: #22c55e; }
.dot.blue { background: #4a90e2; animation: pulse 1.5s infinite; }
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.3} }
.instance-name {
  margin-top: 1.25rem;
  font-size: 0.95rem;
  font-weight: 600;
  color: var(--text);
}
.device-id {
  margin-top: 0.4rem;
  font-size: 0.75rem;
  color: var(--text-dim);
  font-family: monospace;
}
.btn {
  display: inline-block;
  padding: 0.5rem 1.1rem;
  background: #4a90e2;
  color: #fff;
  border: none;
  border-radius: 8px;
  font-size: 0.8rem;
  font-weight: 600;
  cursor: pointer;
  text-decoration: none;
  white-space: nowrap;
}
.btn:hover { background: #3a7bd5; }
.btn-ghost {
  background: transparent;
  border: 1px solid var(--ghost-border);
  color: var(--ghost-text);
  font-size: 0.8rem;
  padding: 0.45rem 1rem;
}
.btn-ghost:hover { border-color: var(--ghost-hover-border); color: var(--ghost-hover-text); }
.btn-danger {
  background: transparent;
  border: 1px solid #7f1d1d;
  color: #ef4444;
  font-size: 0.75rem;
  padding: 0.35rem 0.75rem;
  border-radius: 8px;
  cursor: pointer;
  white-space: nowrap;
}
.btn-danger:hover { border-color: #ef4444; }
.btn-danger-primary {
  background: var(--danger-bg);
  border: none;
  color: var(--danger-text);
  font-size: 0.85rem;
  font-weight: 700;
  padding: 0.5rem 1.5rem;
  border-radius: 8px;
  cursor: pointer;
  white-space: nowrap;
}
.btn-danger-primary:hover { background: var(--danger-hover-bg); color: var(--danger-hover-text); }
.btn-apply {
  font-size: 0.75rem;
  padding: 0.35rem 0.75rem;
}
.btn-link { margin-top: 1.5rem; }
.divider { margin: 1.5rem 0; border: none; border-top: 1px solid var(--divider); }
.hint { font-size: 0.75rem; color: var(--text-sub); margin-top: 0.75rem; }
.integrations { width: 100%; text-align: left; }
.integrations-title {
  font-size: 0.7rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--text-sub);
  margin-bottom: 0.75rem;
}
.int-row {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.55rem 0;
  border-bottom: 1px solid var(--row-border);
}
.int-row:last-child { border-bottom: none; }
.int-label {
  flex: 1;
  font-size: 0.85rem;
  color: var(--text-label);
}
.int-status {
  font-size: 0.7rem;
  padding: 0.18rem 0.5rem;
  border-radius: 999px;
  font-weight: 600;
}
.int-status.pending { background: var(--status-pending-bg); color: var(--status-pending-text); }
.int-status.applied { background: var(--status-applied-bg); color: var(--status-applied-text); }
.unlink-row { margin-top: 1.5rem; }
.page-progress {
  position: fixed;
  top: 0; left: 0; right: 0;
  height: 3px;
  z-index: 200;
  overflow: hidden;
  opacity: 0;
  transition: opacity 0.15s;
  pointer-events: none;
}
.page-progress.active { opacity: 1; }
.page-progress::after {
  content: '';
  position: absolute;
  top: 0; left: -50%;
  width: 50%; height: 100%;
  background: #4a90e2;
  animation: prog 1s ease-in-out infinite;
}
@keyframes prog { 0% { left: -50%; } 100% { left: 100%; } }
.error-msg {
  display: none;
  margin-top: 1rem;
  padding: 0.55rem 0.75rem;
  background: var(--error-bg);
  border: 1px solid var(--error-border);
  border-radius: 8px;
  font-size: 0.78rem;
  color: var(--error-text);
  line-height: 1.5;
  text-align: left;
  word-break: break-word;
}
.error-msg.show { display: block; }
.modal-overlay {
  display: none;
  position: fixed;
  inset: 0;
  background: rgba(0,0,0,0.6);
  align-items: center;
  justify-content: center;
  z-index: 100;
  padding: 1rem;
}
.modal-overlay.open { display: flex; }
.modal {
  background: var(--modal-bg);
  border: 1px solid var(--modal-border);
  border-radius: 12px;
  padding: 1.75rem 1.5rem 1.5rem;
  width: 100%;
  max-width: 420px;
  text-align: left;
}
.modal-title {
  font-size: 0.95rem;
  font-weight: 700;
  color: var(--text);
  margin-bottom: 1.25rem;
}
.info-table { width: 100%; border-collapse: collapse; margin-bottom: 1.25rem; }
.info-table tr td { padding: 0.35rem 0; vertical-align: middle; }
.info-table .lbl { font-size: 0.75rem; color: var(--text-sub); width: 5rem; }
.info-table .val {
  font-size: 0.82rem;
  font-family: monospace;
  color: var(--text-label);
  word-break: break-all;
}
.info-table .copy-cell { width: 2rem; text-align: right; }
.btn-copy {
  background: transparent;
  border: 1px solid var(--copy-border);
  color: var(--copy-text);
  border-radius: 6px;
  padding: 0.18rem 0.45rem;
  font-size: 0.7rem;
  cursor: pointer;
  white-space: nowrap;
}
.btn-copy:hover { border-color: var(--ghost-hover-border); color: var(--ghost-hover-text); }
.btn-copy.copied { border-color: #22c55e; color: #22c55e; }
.tasmota-block { margin-bottom: 1.25rem; }
.tasmota-label {
  font-size: 0.7rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--text-sub);
  margin-bottom: 0.5rem;
}
.tasmota-cmd {
  background: var(--code-bg);
  border: 1px solid var(--code-border);
  border-radius: 8px;
  padding: 0.65rem 0.75rem;
  font-size: 0.72rem;
  font-family: monospace;
  color: var(--code-text);
  word-break: break-all;
  line-height: 1.5;
  margin-bottom: 0.5rem;
}
.modal-actions { display: flex; gap: 0.5rem; justify-content: flex-end; }
.m-body { font-size:0.82rem; color:var(--text-sub); line-height:1.6; margin-bottom:1.25rem; }
.m-list { font-size:0.8rem; color:var(--text-sub); line-height:1.8; padding-left:1.25rem; margin-bottom:1.25rem; }
.m-note { font-size:0.8rem; color:var(--text-sub); line-height:1.6; margin-bottom:0.9rem; }
.m-hint { font-size:0.78rem; color:var(--text-sub); line-height:1.6; margin-bottom:1.25rem; }
.m-em { color:var(--text-label); }
.m-code { color:var(--code-text); font-family:monospace; }
.warn-msg {
  display: none;
  align-items: flex-start;
  gap: 0.5rem;
  padding: 0.55rem 0.75rem;
  background: #2d1f00;
  border: 1px solid #92400e;
  border-radius: 8px;
  font-size: 0.78rem;
  color: #f59e0b;
  line-height: 1.5;
  margin-bottom: 1rem;
}
.warn-msg.show { display: flex; }
[data-theme="light"] .warn-msg { background: #fffbeb; border-color: #d97706; color: #92400e; }
.warn-icon { flex-shrink: 0; }
</style>`;

function renderIntegrationRows(integrations, cfg) {
  return INTEGRATIONS.map(function(it) {
    var status = integrations[it.key] || 'pending';
    var badge = '<span class="int-status ' + status + '">' + status + '</span>';
    var btn;
    if (status === 'pending') {
      var applyFn = it.key === 'mosquitto' ? 'openMosquittoApplyModal()'
                  : it.key === 'zigbee2mqtt' ? 'openZ2mApplyModal()'
                  : it.key === 'vpn' ? 'openVpnApplyModal()'
                  : 'applyIntegration(\'' + it.key + '\')';
      btn = '<button class="btn btn-apply" onclick="' + applyFn + '">Apply</button>';
    } else {
      var extra = '';
      if (it.key === 'mosquitto') {
        extra = '<button class="btn btn-apply" style="margin-right:0.25rem" onclick="openMqttModal()">Device setup</button>';
      } else if (it.key === 'zigbee2mqtt') {
        extra = '<button class="btn btn-apply" style="margin-right:0.25rem" onclick="openZ2mSetupModal()">Device setup</button>';
      } else if (it.key === 'vpn') {
        extra = '<button class="btn btn-apply" style="margin-right:0.25rem" onclick="openVpnSetupModal()">Device setup</button>';
      }
      btn = extra + '<button class="btn-danger" onclick="openIntegrationUnlinkModal(\'' + it.key + '\',\'' + esc(it.label) + '\')">Unlink</button>';
    }
    return '<div class="int-row">' +
           '<span class="int-label">' + esc(it.label) + '</span>' +
           badge + btn +
           '</div>';
  }).join('');
}

function renderUnlinked(deviceId, state) {
  var linkUrl = LINK_BASE
    + '?device=' + encodeURIComponent(deviceId)
    + '&state=' + encodeURIComponent(state);
  var pollUrl = POLL_BASE
    + '?poll=1&device=' + encodeURIComponent(deviceId)
    + '&state=' + encodeURIComponent(state);
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>connecta-m'hi</title>
<script>(function(){var t=window.matchMedia('(prefers-color-scheme:dark)').matches?'dark':'light';document.documentElement.setAttribute('data-theme',t);window.addEventListener('message',function(e){try{if(e.data&&e.data.type==='smhub:setLocalStorage'&&e.data.key==='theme')document.documentElement.setAttribute('data-theme',e.data.value);}catch(x){}});}());</script>
${STYLE}
</head>
<body>
  <div class="card">
    <div class="logo">connecta-<em>m'hi</em></div>
    <div class="sub">SMHUB &rarr; dom.oti.cat</div>
    <div class="badge">
      <span class="dot" id="dot"></span>
      <span id="status">Not linked</span>
    </div>
    <div class="device-id">SMHUB Device id: ${esc(deviceId)}</div>
    <hr class="divider">
    <a href="${esc(linkUrl)}" class="btn btn-link" target="_blank" id="linkBtn">Link to dom.oti.cat</a>
    <div class="hint" id="hint"></div>
  </div>
  <script>
    var pollUrl = ${JSON.stringify(pollUrl)};
    var polling = false;

    function startPolling() {
      if (polling) return;
      polling = true;
      document.getElementById('dot').className = 'dot blue';
      document.getElementById('status').textContent = 'Waiting for link…';
      document.getElementById('hint').textContent = 'Complete the link in the browser tab.';
      poll();
    }

    function poll() {
      fetch(pollUrl)
        .then(function(r) {
          if (r.status === 200) return r.json();
          return null;
        })
        .then(function(data) {
          if (data && data.token) {
            return fetch('/store', {
              method: 'POST',
              headers: {'Content-Type': 'application/json'},
              body: JSON.stringify(data)
            }).then(function() { location.reload(); });
          }
          setTimeout(poll, 2000);
        })
        .catch(function() { setTimeout(poll, 3000); });
    }

    document.getElementById('linkBtn').addEventListener('click', function() {
      var theme = document.documentElement.getAttribute('data-theme') || 'dark';
      this.href = ${JSON.stringify(linkUrl)} + '&theme=' + theme;
      setTimeout(startPolling, 500);
    });
  </script>
</body>
</html>`;
}

function renderLinked(cfg) {
  var integrations = ensureIntegrations(cfg);
  var creds = cfg.credentials || {};
  var smhubIp = getLocalIp() || 'smhub.local';
  var lanSubnet = getLanSubnet();
  var mqttUser = creds.mqtt_user || '';
  var mqttPass = creds.mqtt_password || '';
  var tasmotaCmd = 'Backlog MqttHost ' + smhubIp + '; MqttPort 1883; MqttUser ' + mqttUser + '; MqttPassword ' + mqttPass + '; Restart 1';
  var mac = (cfg.deviceId || '000000000000').replace(/:/g, '');
  var z2mClientId = 'z2m_' + mac;
  var z2mBaseTopic = 'zigbee2mqtt_' + mac;
  var localHaUrl = 'http://' + smhubIp + ':8123';
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>connecta-m'hi</title>
<script>(function(){var t=window.matchMedia('(prefers-color-scheme:dark)').matches?'dark':'light';document.documentElement.setAttribute('data-theme',t);window.addEventListener('message',function(e){try{if(e.data&&e.data.type==='smhub:setLocalStorage'&&e.data.key==='theme')document.documentElement.setAttribute('data-theme',e.data.value);}catch(x){}});}());</script>
${STYLE}
</head>
<body>
  <div id="page-progress" class="page-progress"></div>
  <div class="card">
    <div class="logo">connecta-<em>m'hi</em></div>
    <div class="sub">SMHUB &rarr; dom.oti.cat</div>
    <div class="badge">
      <span class="dot" id="dot"></span>
      <span id="wsstatus">Connecting&hellip;</span>
    </div>
    <div class="instance-name">HA instance: ${esc(cfg.name)}</div>
    <div class="device-id">SMHUB Device id: ${esc(cfg.deviceId)}</div>
    <hr class="divider">
    <div class="integrations">
      <div class="integrations-title">Integrations</div>
      ${renderIntegrationRows(integrations, cfg)}
    </div>
    <div id="error-msg" class="error-msg"></div>
    <div class="unlink-row">
      <button class="btn-danger-primary" onclick="openDeviceUnlinkModal()">Unlink</button>
    </div>
  </div>

  <div class="modal-overlay" id="integrationUnlinkModal">
    <div class="modal">
      <div class="modal-title" id="ium-title">Remove integration?</div>
      <p id="ium-body" class="m-body"></p>
      <div class="modal-actions">
        <button class="btn btn-ghost" onclick="closeIntegrationUnlinkModal()">Cancel</button>
        <button class="btn-danger" style="padding:0.5rem 1.1rem;border-radius:8px;font-size:0.8rem;font-weight:600;cursor:pointer" onclick="confirmIntegrationUnlink()">Remove</button>
      </div>
    </div>
  </div>

  <div class="modal-overlay" id="deviceUnlinkModal">
    <div class="modal">
      <div class="modal-title">Unlink this device?</div>
      <div class="warn-msg show">
        <span class="warn-icon">&#9888;</span>
        <span>If you opened this page remotely via <strong>Open SMHUB</strong>, that connection runs through this link &mdash; unlinking drops it immediately. You&rsquo;ll need to be on the SMHUB&rsquo;s local network to link it again.</span>
      </div>
      <p class="m-body" style="margin-bottom:0.75rem">This will disconnect the SMHUB from <strong class="m-em">${esc(cfg.name)}</strong> and undo all applied integrations:</p>
      <ul class="m-list">
        <li>Zigbee2MQTT &mdash; revert MQTT config to localhost, disable HA discovery</li>
        <li>Mosquitto bridge &mdash; remove listener and bridge config, restart Mosquitto</li>
        <li>LAN proxy &mdash; stop the port forward on port 8123</li>
      </ul>
      <div class="modal-actions">
        <button class="btn btn-ghost" onclick="closeDeviceUnlinkModal()">Cancel</button>
        <button class="btn-danger" style="padding:0.5rem 1.1rem;border-radius:8px;font-size:0.8rem;font-weight:600;cursor:pointer" onclick="confirmDeviceUnlink()">Unlink device</button>
      </div>
    </div>
  </div>

  <div class="modal-overlay" id="mqttApplyModal">
    <div class="modal">
      <div class="modal-title">Enable Mosquitto bridge?</div>
      <p class="m-body">The following changes will be made to Mosquitto and it will be restarted:</p>
      <ul class="m-list">
        <li>Open a listener on <strong class="m-em">port 1883</strong> on all interfaces (LAN accessible)</li>
        <li>Require authentication using the HA instance MQTT credentials</li>
        <li>Bridge <code class="m-code">tele/#</code>, <code class="m-code">stat/#</code>, <code class="m-code">cmnd/#</code> and <code class="m-code">tasmota/#</code> topics to <strong class="m-em">${esc(creds.mqtt_host || '')}:8883</strong></li>
      </ul>
      <div class="modal-actions">
        <button class="btn btn-ghost" onclick="closeMosquittoApplyModal()">Cancel</button>
        <button class="btn" onclick="confirmMosquittoApply()">Apply</button>
      </div>
    </div>
  </div>

  <div class="modal-overlay" id="z2mApplyModal">
    <div class="modal">
      <div class="modal-title">Enable Zigbee2MQTT?</div>
      <p class="m-body">The following will be written to <code class="m-code">configuration.yaml</code> and Zigbee2MQTT will be restarted:</p>
      <table class="info-table" style="margin-bottom:1rem">
        <tr><td class="lbl">base_topic</td><td class="val">${esc(z2mBaseTopic)}</td></tr>
        <tr><td class="lbl">server</td><td class="val">mqtts://${esc(creds.mqtt_host || '')}:8883</td></tr>
        <tr><td class="lbl">user</td><td class="val">${esc(mqttUser)}</td></tr>
        <tr><td class="lbl">client_id</td><td class="val">${esc(z2mClientId)}</td></tr>
        <tr><td class="lbl">ca</td><td class="val">/etc/ssl/certs/ca-certificates.crt</td></tr>
      </table>
      <p class="m-note" style="margin-bottom:1.25rem">HA MQTT discovery will be enabled.</p>
      <div class="modal-actions">
        <button class="btn btn-ghost" onclick="closeZ2mApplyModal()">Cancel</button>
        <button class="btn" onclick="confirmZ2mApply()">Apply</button>
      </div>
    </div>
  </div>

  <div class="modal-overlay" id="vpnApplyModal">
    <div class="modal">
      <div class="modal-title">Enable LAN proxy?</div>
      <div class="warn-msg" id="vpn-apply-conflict">
        <span class="warn-icon">&#9888;</span>
        <span>Conflicts with <strong>d't HUB</strong> &mdash; also routing this subnet via OpenVPN. LAN proxy takes precedence for TCP traffic.</span>
      </div>
      <p class="m-body">The following changes will be made:</p>
      <ul class="m-list">
        <li>Open a port forward on <strong class="m-em">port 8123</strong> &mdash; HA accessible at <code class="m-code">${esc(localHaUrl)}</code></li>
        <li>Route all HA connections to <strong class="m-em">${esc(lanSubnet || 'your home network')}</strong> transparently through SMHUB &mdash; just enter a device&rsquo;s local IP in any integration, no proxy settings needed</li>
      </ul>
      <div class="modal-actions">
        <button class="btn btn-ghost" onclick="closeVpnApplyModal()">Cancel</button>
        <button class="btn" onclick="confirmVpnApply()">Apply</button>
      </div>
    </div>
  </div>

  <div class="modal-overlay" id="vpnSetupModal">
    <div class="modal">
      <div class="modal-title">Local HA access</div>
      <div class="warn-msg" id="vpn-setup-conflict">
        <span class="warn-icon">&#9888;</span>
        <span>Conflicts with <strong>d't HUB</strong> &mdash; also routing this subnet via OpenVPN. LAN proxy takes precedence for TCP traffic.</span>
      </div>
      <table class="info-table">
        <tr>
          <td class="lbl">Local URL</td>
          <td class="val" id="vpn-url">${esc(localHaUrl)}</td>
          <td class="copy-cell"><button class="btn-copy" onclick="copyField('vpn-url',this)">copy</button></td>
        </tr>
        ${lanSubnet ? `<tr>
          <td class="lbl">LAN subnet</td>
          <td class="val">${esc(lanSubnet)}</td>
          <td class="copy-cell"></td>
        </tr>` : ''}
      </table>
      <p class="m-note">Use the Local URL in the Home Assistant companion app as your <strong class="m-em">Local server URL</strong> for instant access when at home.</p>
      <p class="m-note" style="margin-bottom:0">HA can reach any device on <strong class="m-em">${esc(lanSubnet || 'your home network')}</strong> directly &mdash; just enter its local IP address when configuring an integration. Routing is transparent, no proxy settings needed.</p>
      <div class="modal-actions" style="margin-top:1.25rem">
        <button class="btn btn-ghost" onclick="closeVpnSetupModal()">Close</button>
      </div>
    </div>
  </div>

  <div class="modal-overlay" id="mqttModal">
    <div class="modal">
      <div class="modal-title">Connect your devices</div>
      <table class="info-table">
        <tr>
          <td class="lbl">Host</td>
          <td class="val" id="mi-host">${esc(smhubIp)}</td>
          <td class="copy-cell"><button class="btn-copy" onclick="copyField('mi-host',this)">copy</button></td>
        </tr>
        <tr>
          <td class="lbl">Port</td>
          <td class="val">1883</td>
          <td class="copy-cell"><button class="btn-copy" onclick="copyText('1883',this)">copy</button></td>
        </tr>
        <tr>
          <td class="lbl">User</td>
          <td class="val" id="mi-user">${esc(mqttUser)}</td>
          <td class="copy-cell"><button class="btn-copy" onclick="copyField('mi-user',this)">copy</button></td>
        </tr>
        <tr>
          <td class="lbl">Password</td>
          <td class="val" id="mi-pass">${esc(mqttPass)}</td>
          <td class="copy-cell"><button class="btn-copy" onclick="copyField('mi-pass',this)">copy</button></td>
        </tr>
      </table>
      <div class="tasmota-block">
        <div class="tasmota-label">Tasmota &mdash; one-liner</div>
        <div class="tasmota-cmd" id="mi-cmd">${esc(tasmotaCmd)}</div>
        <button class="btn-copy" onclick="copyField('mi-cmd',this)">copy command</button>
      </div>
      <p class="m-hint">Tasmota devices auto-discover in Home Assistant via the MQTT integration. After connecting, each device appears under <strong class="m-em">Settings &rarr; Devices &amp; Services &rarr; MQTT</strong> with its sensors, switches, and controls.</p>
      <div class="modal-actions">
        <button class="btn btn-ghost" onclick="closeMqttModal()">Close</button>
      </div>
    </div>
  </div>

  <div class="modal-overlay" id="z2mSetupModal">
    <div class="modal">
      <div class="modal-title">Connect Zigbee devices</div>
      <div class="m-body" style="margin-bottom:0">
        <p class="m-note"><strong class="m-em">1. Enable pairing mode</strong><br>
        In Home Assistant go to <strong class="m-em">Settings &rarr; Devices &amp; Services &rarr; Zigbee2MQTT</strong>, open the menu and tap <strong class="m-em">Permit join</strong> (active for 60&nbsp;s).</p>
        <p class="m-note"><strong class="m-em">2. Put the device in pairing mode</strong><br>
        Usually hold the reset or pair button for 5&nbsp;s &mdash; check the device manual. The device joins automatically while pairing is open.</p>
        <p class="m-note"><strong class="m-em">3. Device appears in HA</strong><br>
        Paired devices appear under <strong class="m-em">Settings &rarr; Devices &amp; Services &rarr; Zigbee2MQTT</strong> with sensors, switches, and controls auto-created as entities. No extra configuration needed.</p>
        <p style="margin-bottom:0">Manage devices directly from the Zigbee2MQTT frontend at <code class="m-code">http://${esc(smhubIp)}:8080</code>.</p>
      </div>
      <div class="modal-actions" style="margin-top:1.25rem">
        <button class="btn btn-ghost" onclick="closeZ2mSetupModal()">Close</button>
      </div>
    </div>
  </div>

  <script>
    function updateStatus() {
      fetch('/status.json')
        .then(function(r) { return r.json(); })
        .then(function(d) {
          var dot = document.getElementById('dot');
          var st = document.getElementById('wsstatus');
          if (d.connected) {
            dot.className = 'dot green';
            st.textContent = 'Connected';
          } else {
            dot.className = 'dot';
            st.textContent = 'Connecting…';
          }
          var showConflict = !!d.vpnConflict;
          var applyWarn = document.getElementById('vpn-apply-conflict');
          var setupWarn = document.getElementById('vpn-setup-conflict');
          if (applyWarn) applyWarn.classList.toggle('show', showConflict);
          if (setupWarn) setupWarn.classList.toggle('show', showConflict);
        })
        .catch(function() {});
    }
    updateStatus();
    setInterval(updateStatus, 3000);

    var appliedIntegrations = ${JSON.stringify(
      Object.keys(integrations).filter(function(k) { return integrations[k] === 'applied'; })
    )};

    var _pendingUnlinkKey = null;
    var _integrationLabels = { zigbee2mqtt: 'Zigbee2MQTT', mosquitto: 'Mosquitto bridge', vpn: 'LAN proxy' };
    var _integrationRemoveDesc = {
      zigbee2mqtt: 'This will revert the Zigbee2MQTT MQTT config back to localhost:1883, disable HA discovery, and restart Zigbee2MQTT.',
      mosquitto: 'This will remove the Mosquitto listener and bridge config, and restart Mosquitto.',
      vpn: 'This will stop the LAN port forward on port 8123 and remove transparent LAN routing. Your HA instance will no longer be reachable at ${esc(localHaUrl)} from your home network.'
    };

    function openIntegrationUnlinkModal(key, label) {
      _pendingUnlinkKey = key;
      document.getElementById('ium-title').textContent = 'Remove ' + label + '?';
      document.getElementById('ium-body').textContent = _integrationRemoveDesc[key] || 'This will revert the integration.';
      document.getElementById('integrationUnlinkModal').classList.add('open');
    }
    function closeIntegrationUnlinkModal() {
      document.getElementById('integrationUnlinkModal').classList.remove('open');
      _pendingUnlinkKey = null;
    }
    document.getElementById('integrationUnlinkModal').addEventListener('click', function(e) {
      if (e.target === this) closeIntegrationUnlinkModal();
    });
    function confirmIntegrationUnlink() {
      var key = _pendingUnlinkKey;
      closeIntegrationUnlinkModal();
      doPost('/integration/remove', { integration: key })
        .then(function() { location.reload(); })
        .catch(function(e) { showError(e.message); });
    }

    function openDeviceUnlinkModal() {
      document.getElementById('deviceUnlinkModal').classList.add('open');
    }
    function closeDeviceUnlinkModal() {
      document.getElementById('deviceUnlinkModal').classList.remove('open');
    }
    document.getElementById('deviceUnlinkModal').addEventListener('click', function(e) {
      if (e.target === this) closeDeviceUnlinkModal();
    });
    function confirmDeviceUnlink() {
      closeDeviceUnlinkModal();
      clearError();
      startLoading();
      var keys = appliedIntegrations.slice();
      function next() {
        if (!keys.length) {
          return fetch('/unlink', { method: 'POST' }).then(function() { location.reload(); });
        }
        return fetch('/integration/remove', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ integration: keys.shift() })
        }).then(function(r) {
          if (!r.ok) return r.text().then(function(t) { throw new Error(t || 'Remove failed'); });
          return next();
        });
      }
      next().catch(function(e) { showError(e.message); });
    }

    function startLoading() {
      document.getElementById('page-progress').classList.add('active');
    }
    function stopLoading() {
      document.getElementById('page-progress').classList.remove('active');
    }
    function showError(msg) {
      stopLoading();
      var el = document.getElementById('error-msg');
      el.textContent = msg;
      el.classList.add('show');
    }
    function clearError() {
      document.getElementById('error-msg').classList.remove('show');
    }
    function doPost(path, body) {
      clearError();
      startLoading();
      return fetch(path, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(body)
      }).then(function(r) {
        if (!r.ok) return r.text().then(function(t) { throw new Error(t || 'Request failed'); });
      });
    }

    function applyIntegration(key) {
      doPost('/integration/apply', { integration: key })
        .then(function() { location.reload(); })
        .catch(function(e) { showError(e.message); });
    }

    function removeIntegration(key) {
      doPost('/integration/remove', { integration: key })
        .then(function() { location.reload(); })
        .catch(function(e) { showError(e.message); });
    }

    function openMosquittoApplyModal() {
      document.getElementById('mqttApplyModal').classList.add('open');
    }
    function closeMosquittoApplyModal() {
      document.getElementById('mqttApplyModal').classList.remove('open');
    }
    document.getElementById('mqttApplyModal').addEventListener('click', function(e) {
      if (e.target === this) closeMosquittoApplyModal();
    });
    function confirmMosquittoApply() {
      closeMosquittoApplyModal();
      doPost('/integration/apply', { integration: 'mosquitto' })
        .then(function() { location.reload(); })
        .catch(function(e) { showError(e.message); });
    }

    function openZ2mApplyModal() {
      document.getElementById('z2mApplyModal').classList.add('open');
    }
    function closeZ2mApplyModal() {
      document.getElementById('z2mApplyModal').classList.remove('open');
    }
    document.getElementById('z2mApplyModal').addEventListener('click', function(e) {
      if (e.target === this) closeZ2mApplyModal();
    });
    function confirmZ2mApply() {
      closeZ2mApplyModal();
      doPost('/integration/apply', { integration: 'zigbee2mqtt' })
        .then(function() { location.reload(); })
        .catch(function(e) { showError(e.message); });
    }

    function openVpnApplyModal() {
      document.getElementById('vpnApplyModal').classList.add('open');
    }
    function closeVpnApplyModal() {
      document.getElementById('vpnApplyModal').classList.remove('open');
    }
    document.getElementById('vpnApplyModal').addEventListener('click', function(e) {
      if (e.target === this) closeVpnApplyModal();
    });
    function confirmVpnApply() {
      closeVpnApplyModal();
      doPost('/integration/apply', { integration: 'vpn' })
        .then(function() { location.reload(); })
        .catch(function(e) { showError(e.message); });
    }

    function openVpnSetupModal() {
      document.getElementById('vpnSetupModal').classList.add('open');
    }
    function closeVpnSetupModal() {
      document.getElementById('vpnSetupModal').classList.remove('open');
    }
    document.getElementById('vpnSetupModal').addEventListener('click', function(e) {
      if (e.target === this) closeVpnSetupModal();
    });

    function openZ2mSetupModal() {
      document.getElementById('z2mSetupModal').classList.add('open');
    }
    function closeZ2mSetupModal() {
      document.getElementById('z2mSetupModal').classList.remove('open');
    }
    document.getElementById('z2mSetupModal').addEventListener('click', function(e) {
      if (e.target === this) closeZ2mSetupModal();
    });

    function openMqttModal() {
      document.getElementById('mqttModal').classList.add('open');
    }
    function closeMqttModal() {
      document.getElementById('mqttModal').classList.remove('open');
    }
    document.getElementById('mqttModal').addEventListener('click', function(e) {
      if (e.target === this) closeMqttModal();
    });

    function copyText(text, btn) {
      navigator.clipboard.writeText(text).then(function() {
        var orig = btn.textContent;
        btn.textContent = '✓';
        btn.classList.add('copied');
        setTimeout(function() { btn.textContent = orig; btn.classList.remove('copied'); }, 1500);
      });
    }
    function copyField(id, btn) {
      copyText(document.getElementById(id).textContent, btn);
    }
  </script>
</body>
</html>`;
}

// --- WebSocket client (Node.js 22 built-in global WebSocket) ---
var WS_CONNECT_TIMEOUT_MS = 10000;
var wsConn = null;
var wsConnected = false;
var wsBackoff = 2000;
var wsReconnectTimer = null;
var wsConnectTimer = null;
var wsGen = 0;
var vpnConflict = null;

function wsConnect() {
  var cfg = loadConfig();
  if (!cfg.token || !cfg.wsUrl) return;
  if (wsConn) return;

  var myGen = ++wsGen;
  var sock;
  try {
    sock = new WebSocket(cfg.wsUrl);
  } catch (e) {
    process.stdout.write('ws connect error: ' + e.message + '\n');
    wsScheduleReconnect();
    return;
  }
  wsConn = sock;

  // Guards against a hung handshake (no open/close/error ever fires, e.g. after
  // a network blip) leaving wsConn stuck non-null with no further reconnects.
  wsConnectTimer = setTimeout(function() {
    if (myGen !== wsGen) return;
    wsGen++;
    try { sock.close(); } catch (e) {}
    wsConn = null;
    wsConnected = false;
    process.stdout.write('ws connect timed out, retry in ' + wsBackoff + 'ms\n');
    wsScheduleReconnect();
  }, WS_CONNECT_TIMEOUT_MS);

  sock.addEventListener('open', function() {
    if (myGen !== wsGen) return;
    clearTimeout(wsConnectTimer);
    var cfg = loadConfig();
    wsConnected = true;
    wsBackoff = 2000;
    sock.send(JSON.stringify({ type: 'hello', device_id: deviceId, token: cfg.token, lan_ip: getLocalIp() }));
    process.stdout.write('ws connected to ' + cfg.wsUrl + '\n');
  });

  sock.addEventListener('message', function(ev) {
    if (myGen !== wsGen) return;
    try {
      var msg = JSON.parse(ev.data);
      if (msg.type === 'ping') {
        sock.send(JSON.stringify({ type: 'pong' }));
      } else if (msg.type === 'welcome') {
        var cfg = loadConfig();
        if (cfg.integrations && cfg.integrations.vpn === 'applied') sendSubnet();
      } else if (msg.type === 'subnet_conflict') {
        vpnConflict = msg.iface || null;
      } else if (msg.type === 'socks5') {
        handleSocks5Frame(msg);
      } else if (msg.type === 'proxy') {
        handleProxyFrame(msg);
      }
    } catch {}
  });

  sock.addEventListener('close', function() {
    if (myGen !== wsGen) return;
    wsGen++;
    clearTimeout(wsConnectTimer);
    wsConn = null;
    wsConnected = false;
    proxyConns.forEach(function(e) { e.socket.destroy(); });
    proxyConns.clear();
    socks5Conns.forEach(function(s) { s.destroy(); });
    socks5Conns.clear();
    process.stdout.write('ws closed, retry in ' + wsBackoff + 'ms\n');
    wsScheduleReconnect();
  });

  sock.addEventListener('error', function() {
    // close event fires after error
  });
}

function wsScheduleReconnect() {
  if (wsReconnectTimer) return;
  wsReconnectTimer = setTimeout(function() {
    wsReconnectTimer = null;
    wsConnect();
  }, wsBackoff);
  wsBackoff = Math.min(wsBackoff * 2, 60000);
}

function wsStop() {
  wsGen++;
  if (wsConnectTimer) { clearTimeout(wsConnectTimer); wsConnectTimer = null; }
  if (wsReconnectTimer) { clearTimeout(wsReconnectTimer); wsReconnectTimer = null; }
  if (wsConn) { wsConn.close(); wsConn = null; }
  wsConnected = false;
  wsBackoff = 2000;
  proxyConns.forEach(function(e) { e.socket.destroy(); });
  proxyConns.clear();
  socks5Conns.forEach(function(s) { s.destroy(); });
  socks5Conns.clear();
}

// --- Request handler ---
const deviceId = getDeviceId();

function readBody(req) {
  return new Promise(function(resolve) {
    var chunks = [];
    req.on('data', function(c) { chunks.push(c); });
    req.on('end', function() { resolve(Buffer.concat(chunks).toString()); });
  });
}

const server = http.createServer(function(req, res) {
  var url = new URL(req.url, 'http://' + req.headers.host);

  if (url.pathname === '/store' && req.method === 'POST') {
    readBody(req).then(function(raw) {
      try {
        var data = JSON.parse(raw);
        if (!data.token || !data.name || !data.ws) throw new Error('bad');
        var cfg = loadConfig();
        cfg.token = data.token;
        cfg.name = data.name;
        cfg.wsUrl = data.ws;
        cfg.deviceId = deviceId;
        cfg.linkedAt = new Date().toISOString();
        cfg.integrations = { zigbee2mqtt: 'pending', mosquitto: 'pending', vpn: 'pending' };
        delete cfg.state;
        saveConfig(cfg);
        wsStop();
        wsConnect();
        fetchCredentials().then(function() {
          res.writeHead(200, { 'Content-Type': 'text/plain' });
          res.end('ok');
        });
      } catch {
        res.writeHead(400);
        res.end('bad request');
      }
    });
    return;
  }

  if (url.pathname === '/unlink' && req.method === 'POST') {
    var unlinkCfg = loadConfig();
    wsStop();
    removeVpn();
    // Revoke the token server-side before we discard it locally (best-effort — never blocks unlink).
    revokeToken(unlinkCfg).then(function() {
      saveConfig({});
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('ok');
    });
    return;
  }

  if (url.pathname === '/integration/apply' && req.method === 'POST') {
    readBody(req).then(function(raw) {
      try {
        var data = JSON.parse(raw);
        var key = data.integration;
        if (!INTEGRATIONS.find(function(i) { return i.key === key; })) throw new Error('unknown');
        var cfg = loadConfig();
        ensureIntegrations(cfg);
        if (key === 'mosquitto') applyMosquitto(cfg);
        else if (key === 'zigbee2mqtt') applyZigbee2mqtt(cfg);
        else if (key === 'vpn') applyVpn();
        cfg.integrations[key] = 'applied';
        saveConfig(cfg);
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('ok');
      } catch (e) {
        process.stdout.write('integration apply error: ' + e.message + '\n');
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end(e.message);
      }
    });
    return;
  }

  if (url.pathname === '/integration/remove' && req.method === 'POST') {
    readBody(req).then(function(raw) {
      try {
        var data = JSON.parse(raw);
        var key = data.integration;
        if (!INTEGRATIONS.find(function(i) { return i.key === key; })) throw new Error('unknown');
        var cfg = loadConfig();
        ensureIntegrations(cfg);
        if (key === 'mosquitto') removeMosquitto();
        else if (key === 'zigbee2mqtt') removeZigbee2mqtt();
        else if (key === 'vpn') removeVpn();
        cfg.integrations[key] = 'pending';
        saveConfig(cfg);
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('ok');
      } catch (e) {
        process.stdout.write('integration remove error: ' + e.message + '\n');
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end(e.message);
      }
    });
    return;
  }

  if (url.pathname === '/status.json') {
    var sc = loadConfig();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ connected: wsConnected, hasCredentials: !!(sc.credentials && sc.credentials.mqtt_user), vpnConflict: vpnConflict }));
    return;
  }

  if (url.pathname === '/' && req.method === 'GET') {
    var cfg = loadConfig();
    var html;
    if (cfg.token) {
      html = renderLinked(cfg);
    } else {
      var state = ensureState(cfg);
      html = renderUnlinked(deviceId, state);
    }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(html);
    return;
  }

  res.writeHead(404);
  res.end();
});

server.listen(PORT, '0.0.0.0', function() {
  process.stdout.write('oticonnect listening on :' + PORT + ' (device: ' + deviceId + ')\n');
  var cfg = loadConfig();
  wsConnect();
  if (cfg.integrations && cfg.integrations.vpn === 'applied') applyVpn();
  // Refresh credentials (best-effort), then re-assert applied integrations to heal any config
  // drift from an SMHUB upgrade. fetchCredentials always resolves, so reconcile runs regardless.
  fetchCredentials().then(reconcileIntegrations);
});

process.on('SIGTERM', function() {
  wsStop();
  removeVpn();
  server.close(function() { process.exit(0); });
});
