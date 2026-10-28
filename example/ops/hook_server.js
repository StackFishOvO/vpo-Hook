// 运维脚本示例（Node）：用 vpoh 生成网络出口 hook，跑一个 HTTP 服务，
// 外发消息里的敏感词（password）会被就地改成 HONEYPOT。
//
// 用法（在项目根目录）:
//   node example/ops/hook_server.js [port]
// 然后浏览器打开:
//   http://127.0.0.1:<port>/send?msg=my+password+123
'use strict';

const path = require('path');
const vpoh = require('../../js/vpoh.js');

const ROOT = path.join(__dirname, '..', '..');
const PORT = process.argv[2] || '8080';
const server = path.join(ROOT, 'example', 'servers', 'demo_server.js');

// 1. 定制一个"网络出口"hook：只拦 send/sendto/write/writev
const manifest = {
  pkg: { name: 'net-egress' },
  symbols: ['send', 'sendto', 'write', 'writev'],
  apis: {},
  deps: [],
};
const r = vpoh.generate(manifest, path.join(ROOT, 'example', 'servers', '.vpo'));
console.log('hook:', r.so);

// 2. 外发数据改成蜜罐模式（默认是 block）
process.env.VPO_DATA_MODE = 'honeypot';

// 3. 用这个定制 hook 跑服务器
console.log(`打开浏览器: http://127.0.0.1:${PORT}/send?msg=my+password+123`);
vpoh.run(['node', server, PORT], true, r.so);
