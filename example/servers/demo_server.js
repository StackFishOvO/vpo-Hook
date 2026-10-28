// vpo-hook 外发蜜罐 demo 服务器（纯标准库，无依赖）。
// 用法: node demo_server.js [port]
'use strict';

const http = require('http');
const url = require('url');

const PORT = Number(process.argv[2]) || 8080;

http.createServer((req, res) => {
  const u = url.parse(req.url, true);
  if (u.pathname === '/send') {
    const msg = u.query.msg || 'hello password 123';
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8', 'Connection': 'close' });
    res.end('sent: ' + msg + '\n');
  } else {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Connection': 'close' });
    res.end(
      '<h1>vpo-hook 外发蜜罐 demo</h1>' +
      '<p><a href="/send?msg=my+password+123">/send?msg=my+password+123</a></p>',
    );
  }
}).listen(PORT, '127.0.0.1', () => console.log('listening on', PORT));
