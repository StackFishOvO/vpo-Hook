'use strict';

/*
 * Node HTTP 应用：故意把 crypto_pkg 的密文作为 /leak 响应返回。
 *
 * 这里不手动检查 taint。拦截由 ns_guard patch
 * http.ServerResponse.write/end 完成。
 *
 * 如果 sink 抛 NamespaceDenied，handler 返回 403 BLOCKED，
 * 这样测试能清楚看到“数据没有进入响应”。
 */

const http = require('http');
const cryptoPkg = require('./crypto_pkg');

const SECRET = Buffer.from('password=REAL_SECRET_123');

function handler(req, res) {
  try {
    if (req.url === '/leak') {
      const ciphertext = cryptoPkg.encrypt(SECRET);
      res.end(ciphertext);
      return;
    }
    if (req.url === '/safe') {
      res.end('SAFE');
      return;
    }
    res.statusCode = 404;
    res.end('NOT_FOUND');
  } catch (err) {
    if (err && err.code === 'NAMESPACE_DENIED') {
      res.statusCode = 403;
      res.end('BLOCKED');
      return;
    }
    throw err;
  }
}

function createServer() {
  return http.createServer(handler);
}

module.exports = { createServer, SECRET };
