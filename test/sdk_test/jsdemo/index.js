/* SDK 测试包：暴露敏感行为，供 discover 反射候选面 */
'use strict';

const fs = require('fs');
const cp = require('child_process');

module.exports = {
  readFile: (p) => fs.readFileSync(p, 'utf8'),
  exec: (c) => cp.execSync(c).toString(),
};
