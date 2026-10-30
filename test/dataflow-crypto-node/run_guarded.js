'use strict';

// 防护组：安装 namespace guard（或由 vpo-hook preload 自动安装）。
require('./run_case').run(true).catch((err) => {
  console.error(err);
  process.exit(1);
});
