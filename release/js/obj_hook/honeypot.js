#!/usr/bin/env node
/*
 * VPO-Hook 蜜罐运维脚本（明文版）。
 *
 * 与 py/obj_hook/honeypot.py 逻辑一致：生成蜜罐数据到 ~/.vpo-hook/honeypot/。
 * 用户在 run 前由启动器调用。可自由编辑，定制诱饵数据源。
 */

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

const HONEYPOT_DIR = path.join(os.homedir(), '.vpo-hook', 'honeypot');

function generate() {
  fs.mkdirSync(HONEYPOT_DIR, { recursive: true });

  fs.writeFileSync(
    path.join(HONEYPOT_DIR, 'passwd'),
    'root:x:0:0:HONEYPOT:/root:/bin/false\n' +
      'honeypot:x:1000:1000:HONEYPOT:/home/honeypot:/bin/false\n',
  );

  const ssh = path.join(HONEYPOT_DIR, 'ssh');
  fs.mkdirSync(ssh, { recursive: true });
  fs.writeFileSync(
    path.join(ssh, 'id_rsa'),
    '-----BEGIN OPENSSH PRIVATE KEY-----\n' +
      'HONEYPOT FAKE KEY\n' +
      '-----END OPENSSH PRIVATE KEY-----\n',
  );

  const aws = path.join(HONEYPOT_DIR, 'aws');
  fs.mkdirSync(aws, { recursive: true });
  fs.writeFileSync(
    path.join(aws, 'credentials'),
    '[default]\n' +
      'aws_access_key_id = HONEYPOT\n' +
      'aws_secret_access_key = HONEYPOT\n',
  );

  const testdata = path.join(HONEYPOT_DIR, 'testdata');
  fs.mkdirSync(testdata, { recursive: true });
  fs.writeFileSync(path.join(testdata, 'secret.txt'), 'api_token=HONEYPOT_FAKE_000\n');
  fs.writeFileSync(path.join(testdata, 'db.txt'), 'password=HONEYPOT_FAKE_111\n');

  const sensitive = path.join(HONEYPOT_DIR, 'sensitive');
  fs.mkdirSync(sensitive, { recursive: true });
  fs.writeFileSync(
    path.join(sensitive, 'secret.txt'),
    'database_password=HONEYPOT_FAKE\n' +
      'api_key=HONEYPOT_FAKE\n' +
      'aws_secret_access_key=HONEYPOT_FAKE\n',
  );

  console.log('[honeypot] 蜜罐数据已生成');
}

generate();
