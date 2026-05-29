const { parentPort, workerData } = require('worker_threads');
const fs = require('fs').promises;
const net = require('net');
const axios = require('axios');

async function checkProxy(proxy) {
  const [host, port] = proxy.split(':');
  // 1. TCP connect test
  const tcpOk = await new Promise(resolve => {
    const socket = new net.Socket();
    const timeout = setTimeout(() => { socket.destroy(); resolve(false); }, 2000);
    socket.once('connect', () => { clearTimeout(timeout); socket.destroy(); resolve(true); });
    socket.once('error', () => { clearTimeout(timeout); socket.destroy(); resolve(false); });
    socket.connect(parseInt(port), host);
  });
  if (!tcpOk) return false;

  // 2. HTTP check via proxy (works for HTTP proxies)
  try {
    const response = await axios.get('http://httpbin.org/get', {
      proxy: { host, port: parseInt(port) },
      timeout: 3000
    });
    return response.status === 200;
  } catch {
    return false;
  }
}

(async () => {
  const { inputFile, outputFile } = workerData;
  let proxies;
  try {
    const data = await fs.readFile(inputFile, 'utf8');
    proxies = data.split('\n').map(l => l.trim()).filter(l => l);
  } catch (err) {
    parentPort.postMessage({ type: 'error', error: err.message });
    return;
  }

  const total = proxies.length;
  let alive = 0, dead = 0;
  const results = [];
  const CONCURRENT = 500;
  for (let i = 0; i < proxies.length; i += CONCURRENT) {
    const batch = proxies.slice(i, i + CONCURRENT);
    const checks = batch.map(async proxy => {
      const ok = await checkProxy(proxy);
      if (ok) { alive++; results.push(proxy); } else dead++;
      parentPort.postMessage({ type: 'progress', alive, dead, total });
    });
    await Promise.all(checks);
  }

  await fs.writeFile(outputFile, results.join('\n'));
  parentPort.postMessage({ type: 'result', alive, dead, total });
})();
