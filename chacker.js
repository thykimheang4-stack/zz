const fs = require('fs').promises;
const axios = require('axios');  // npm install axios

const INPUT_FILE = 'proxies.txt';
const OUTPUT_FILE = 'proxy.txt';
const TIMEOUT = 5000;            // ms
const CONCURRENT_CHECKS = 200;
const TEST_URL = 'http://httpbin.org/get';

let total = 0;
let alive = 0;
let dead = 0;

// Simple progress display (updates every second)
function showProgress() {
    const percent = total ? ((alive + dead) / total * 100).toFixed(1) : 0;
    process.stdout.write(`\rProgress: ${alive + dead}/${total} (${percent}%) | Alive: ${alive} | Dead: ${dead}`);
}

async function checkProxy(proxy) {
    const start = Date.now();
    try {
        const response = await axios.get(TEST_URL, {
            proxy: {
                host: proxy.split(':')[0],
                port: parseInt(proxy.split(':')[1], 10)
            },
            timeout: TIMEOUT
        });
        if (response.status === 200) {
            const latency = Date.now() - start;
            // Incremental save
            await fs.appendFile(OUTPUT_FILE, proxy + '\n');
            alive++;
            return { proxy, alive: true, latency };
        }
    } catch (err) {
        // ignore
    }
    dead++;
    return { proxy, alive: false };
}

async function main() {
    // Load proxies
    let proxies;
    try {
        const data = await fs.readFile(INPUT_FILE, 'utf8');
        proxies = data.split('\n').map(line => line.trim()).filter(line => line);
    } catch (err) {
        console.error(`Error: ${INPUT_FILE} not found.`);
        return;
    }

    total = proxies.length;
    console.log(`Loaded ${total} proxies. Starting check...\n`);

    // Clear output file
    await fs.writeFile(OUTPUT_FILE, '');

    // Process in batches to control concurrency
    const results = [];
    for (let i = 0; i < proxies.length; i += CONCURRENT_CHECKS) {
        const batch = proxies.slice(i, i + CONCURRENT_CHECKS);
        const batchPromises = batch.map(proxy => checkProxy(proxy));
        const batchResults = await Promise.all(batchPromises);
        results.push(...batchResults);
        showProgress();
    }

    console.log('\n' + '='.repeat(40));
    console.log(`Finished! Alive: ${alive} | Dead: ${dead}`);
    console.log(`Results saved incrementally to ${OUTPUT_FILE}`);
}

main().catch(console.error);
