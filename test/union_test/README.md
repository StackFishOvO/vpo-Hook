# union_test — 功能合集测试

每个脚本独立、可单独跑，一眼能看出在测什么。

## 怎么跑

```bash
# 先构建（一次性）
bash test/union_test/00_build.sh

# 单独跑某个功能
bash test/union_test/01_file_honeypot.sh

# 全部跑
bash test/union_test/run_all.sh
```

每个脚本结尾都会打印 `PASS=N FAIL=N`。

## 功能对照

| 脚本 | 测什么 |
|---|---|
| `00_build.sh` | 生成 wrapper + 编译 hook 库 + 自检 |
| `01_file_honeypot.sh` | 文件读蜜罐：Python open/os.open、Node fs、cat、C fopen64 |
| `02_child_env.sh` | 子进程逃逸拦截：execve/Popen/posix_spawn/env -i/execv/execvp |
| `03_network_exec.sh` | 网络三态（off/internet/allowlist、loopback）+ exec 模式 |
| `04_env_scope.sh` | env 作用域、/etc 放行、敏感 deny + 蜜罐、写标记 0 字节 |
| `05_pickle_native.sh` | pickle RCE + C 扩展(.so)/shell/node addon 蜜罐 |
| `06_audit_grant.sh` | deny → denials.log → 摘要 → log/grant/list/revoke |
| `07_signing_chain.sh` | 配置签名 + 审计链（篡改可检测） |
| `08_scan_sources.sh` | 能力扫描 + L2 信源（deny-only） |
| `09_sdk_cli.sh` | SDK discover/generate + CLI 子命令 + init --profile 模板 |

## 说明

- 用临时 HOME/临时目录，不碰你真实的 `~/.vpo-hook`。
- `05` 的 node addon 需要 `node-gyp`（没有会自动 SKIP）。
- `03` 里 internet 公网 80 是“放行”验证：本机没外网会 timeout/refused，只要不是 `Operation not permitted` 就算放行。
