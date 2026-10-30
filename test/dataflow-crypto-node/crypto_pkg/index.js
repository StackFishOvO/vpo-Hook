'use strict';

/*
 * 测试用“具备加密能力的 Node 包”。
 *
 * 使用 AES-256-GCM 真正加密；密文里不会残留 password/token 明文。
 * taint 由 vpo-hook 的 ns_guard 在包边界统一添加，包本身不参与策略。
 */

const crypto = require('crypto');

const KEY = crypto.randomBytes(32);

function encrypt(data) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  const body = Buffer.concat([cipher.update(Buffer.from(data)), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), body]);
}

function decrypt(token) {
  const iv = token.subarray(0, 12);
  const tag = token.subarray(12, 28);
  const body = token.subarray(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', KEY, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(body), decipher.final()]);
}

module.exports = { encrypt, decrypt };
