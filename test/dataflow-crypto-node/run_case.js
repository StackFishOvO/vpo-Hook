'use strict';

/*
 * 启动本地 http server，分别请求 /leak 和 /safe。
 *
 * guarded=false：不安装 ns_guard，密文正常返回。
 * guarded=true ：安装 ns_guard，密文在 res.end() sink 被拒，返回 403 BLOCKED。
 */

const http = require('http');
const path = require('path');

function request(server, pathname) {
  return new Promise((resolve, reject) => {
    const { port } = server.address();
    http.get({ host: '127.0.0.1', port, path: pathname }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks) }));
    }).on('error', reject);
  });
}

async function run(guarded) {
  if (guarded && !process.env.VPO_NS_POLICY) {
    const nsGuard = require('../../js/plaintext/ns_guard.js');
    nsGuard.installFromFile(path.join(__dirname, 'ns_policy.json'));
  }

  const { createServer } = require('./server');
  const server = createServer();
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));

  try {
    const leak = await request(server, '/leak');
    const label = guarded ? 'GUARDED' : 'BASELINE';
    console.log(`${label} status=${leak.status} body_hex=${leak.body.subarray(0, 24).toString('hex')}`);

    if (guarded) {
      if (leak.status !== 403 || leak.body.toString() !== 'BLOCKED') {
        throw new Error(`guarded leak was not blocked: ${leak.status} ${leak.body.toString()}`);
      }
    } else {
      if (leak.status !== 200) throw new Error(`baseline status ${leak.status}`);
      if (leak.body.includes(Buffer.from('password'))) {
        throw new Error('ciphertext unexpectedly contains plaintext marker');
      }
    }

    const safe = await request(server, '/safe');
    console.log(`${label}_SAFE status=${safe.status} body=${safe.body.toString()}`);
    if (safe.status !== 200 || safe.body.toString() !== 'SAFE') {
      throw new Error('safe route broken');
    }
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

module.exports = { run };
