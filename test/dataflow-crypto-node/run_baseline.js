'use strict';

// 对照组：不安装 namespace guard，密文应正常进入 HTTP response。
require('./run_case').run(false).catch((err) => {
  console.error(err);
  process.exit(1);
});
