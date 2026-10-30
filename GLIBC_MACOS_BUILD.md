# 老 glibc 与 macOS 预编译构建指南

> 状态：设计/待实现。当前 `vpo-hook init` 仍然只做本机编译；下面的目录和
> fallback 逻辑还没有接入。本文档保留给 AI/交接使用，避免这部分知识只存在于
> 已忽略的 `addition.md` 6.2。
>
> 运行时迁移（macOS → Linux、同名符号、LFS 别名、验证步骤）见
> `LINUX_MIGRATION.md`；本文只讲**发布侧预编译产物**。

---

## 1. 目标

发布包需要同时满足：

1. **本机编译优先**：用户有 gcc/clang 时，`init` 在本机编译，避免 libc 不匹配。
2. **预编译库兜底**：用户没有编译器或本机编译失败时，使用随包分发的
   `prebuilt/<platform>-<arch>/` 产物。
3. **Linux 兼容旧 glibc**：发布用 `.so` 不能在新 Linux 上直接编译，否则
   `GLIBC_2.xx` 符号版本太新，旧发行版加载失败。
4. **macOS 双架构**：arm64 和 x86_64 都要有 `.dylib`；可选 universal binary。
5. **可验证**：预编译库要有 hash/签名，运行时能校验；构建过程可复现。

明确不做：

- Windows
- musl/Alpine（先不在目标内）
- 用本机新 Linux 生成发布产物

---

## 2. 产物目录

```text
prebuilt/
  linux-x86_64/
    libvpo_hook.so
    SHA256SUMS
  linux-aarch64/
    libvpo_hook.so
    SHA256SUMS
  darwin-arm64/
    libvpo_hook.dylib
    SHA256SUMS
  darwin-x86_64/
    libvpo_hook.dylib
    SHA256SUMS
```

文件名必须和运行时查找逻辑一致：

- Linux：`libvpo_hook.so`
- macOS：`libvpo_hook.dylib`

运行时优先查找用户目录 `~/.vpo-hook/lib/`，再兼容包内 `obj_hook/`；
预编译 fallback 应该把选中的库放到这两个位置之一，并记录来源。

---

## 3. Linux x86_64：旧 glibc 容器

### 3.1 先生成 wrapper.c

```bash
cd /path/to/vpoh
python3 py/obj_hook/gen_wrappers.py \
  py/obj_hook/signatures.json \
  -o prebuilt/linux-x86_64/wrapper.c \
  -p linux
```

### 3.2 manylinux2014（glibc 2.17）

推荐用旧 glibc 容器，不要在用户/开发机的新 Linux 上直接编译发布产物。

```bash
mkdir -p prebuilt/linux-x86_64
docker run --rm -v "$PWD:/src" -w /src quay.io/pypa/manylinux2014_x86_64 \
  bash -lc 'gcc -shared -fPIC -O2 \
    -I py/obj_hook \
    -o prebuilt/linux-x86_64/libvpo_hook.so \
    prebuilt/linux-x86_64/wrapper.c \
    py/obj_hook/policy.c \
    -ldl'
```

### 3.3 ubuntu:18.04 备选（glibc 2.27）

```bash
docker run --rm -v "$PWD:/src" -w /src ubuntu:18.04 \
  bash -lc 'apt-get update && apt-get install -y gcc && \
    gcc -shared -fPIC -O2 \
      -I py/obj_hook \
      -o prebuilt/linux-x86_64/libvpo_hook.so \
      prebuilt/linux-x86_64/wrapper.c \
      py/obj_hook/policy.c \
      -ldl'
```

### 3.4 无 Docker：zig cc

```bash
zig cc -target x86_64-linux-gnu.2.17 \
  -shared -fPIC -O2 \
  -I py/obj_hook \
  -o prebuilt/linux-x86_64/libvpo_hook.so \
  prebuilt/linux-x86_64/wrapper.c \
  py/obj_hook/policy.c \
  -ldl
```

生成后仍然要验证符号版本，不能只看“编译成功”。

### 3.5 验证

```bash
# 最高 GLIBC 符号版本
readelf --version-info prebuilt/linux-x86_64/libvpo_hook.so | grep GLIBC_ | sort -V | tail

# 动态符号
objdump -T prebuilt/linux-x86_64/libvpo_hook.so | grep -E 'open64|openat64|fopen|fopen64'

# 旧容器里能加载
docker run --rm -v "$PWD:/src" -w /src quay.io/pypa/manylinux2014_x86_64 \
  bash -lc 'LD_PRELOAD=/src/prebuilt/linux-x86_64/libvpo_hook.so /bin/true && echo OK'

# 功能 smoke test（在目标容器/发行版里）
LD_PRELOAD=prebuilt/linux-x86_64/libvpo_hook.so \
  VPO_HOOK_CONFIG=/tmp/vpo-config.yaml \
  cat /etc/passwd
```

---

## 4. Linux arm64

可选方案：

1. 原生 arm64 runner（最稳）
2. `docker run --platform linux/arm64` + QEMU（慢，但可用）
3. `aarch64-linux-gnu-gcc` + 旧 sysroot 交叉编译

```bash
docker run --rm --platform linux/arm64 -v "$PWD:/src" -w /src \
  quay.io/pypa/manylinux2014_aarch64 \
  bash -lc 'gcc -shared -fPIC -O2 \
    -I py/obj_hook \
    -o prebuilt/linux-aarch64/libvpo_hook.so \
    prebuilt/linux-aarch64/wrapper.c \
    py/obj_hook/policy.c \
    -ldl'
```

同样要跑 `readelf --version-info` 和 `nm -D` 验证。

---

## 5. macOS

### 5.1 生成 wrapper.c

```bash
python3 py/obj_hook/gen_wrappers.py \
  py/obj_hook/signatures.json \
  -o prebuilt/darwin-arm64/wrapper.c \
  -p darwin
```

x86_64 可以复用同一份 `wrapper.c`。

### 5.2 分架构构建

```bash
# arm64
clang -dynamiclib -arch arm64 \
  -I py/obj_hook \
  -o prebuilt/darwin-arm64/libvpo_hook.dylib \
  prebuilt/darwin-arm64/wrapper.c \
  py/obj_hook/policy.c

# x86_64
clang -dynamiclib -arch x86_64 \
  -I py/obj_hook \
  -o prebuilt/darwin-x86_64/libvpo_hook.dylib \
  prebuilt/darwin-x86_64/wrapper.c \
  py/obj_hook/policy.c
```

universal binary 可选：

```bash
clang -dynamiclib -arch arm64 -arch x86_64 \
  -I py/obj_hook \
  -o prebuilt/darwin-universal/libvpo_hook.dylib \
  prebuilt/darwin-arm64/wrapper.c \
  py/obj_hook/policy.c
```

### 5.3 签名 / SIP / DYLD 限制

- `DYLD_INSERT_LIBRARIES` 对受 SIP/hardened runtime 保护的系统二进制无效。
- 用户自己的 Node/Python（Homebrew、nvm、pyenv、python.org）通常可注入，但要实测。
- 预编译 dylib 建议至少做 ad-hoc 签名，避免部分环境直接拒绝：

```bash
codesign --force --sign - prebuilt/darwin-arm64/libvpo_hook.dylib
codesign --force --sign - prebuilt/darwin-x86_64/libvpo_hook.dylib
```

- macOS 上部分函数无法安全 interpose（例如 `close/mmap/mprotect` 属于 dyld
  加载期必需；另有一组函数没有安全别名）。这些是已接受边界，不要为了“全拦”
  把进程启动搞崩。

### 5.4 验证

```bash
otool -L prebuilt/darwin-arm64/libvpo_hook.dylib
nm -gU prebuilt/darwin-arm64/libvpo_hook.dylib | grep -E 'open|read|write|connect|execve'

# 用真实 Node/Python 跑
DYLD_INSERT_LIBRARIES=prebuilt/darwin-arm64/libvpo_hook.dylib \
VPO_HOOK_CONFIG=/tmp/vpo-config.yaml \
python3 -c "print(open('/etc/passwd').read()[:20])"
```

macOS 回归至少覆盖：

- Python `open` / `os.open` / `subprocess`
- Node `fs.readFileSync` / `child_process`
- 子进程环境继承
- `--config` / `--ns-policy`
- inbound 检查
- 简单组蜜罐

---

## 6. `init` 的 fallback 设计（待实现）

伪代码：

```text
def build_or_fallback():
    try:
        return build_hook_locally()
    except (NoCompiler, CompileError):
        return install_prebuilt(platform, arch)

def install_prebuilt(platform, arch):
    src = package_root / "prebuilt" / f"{platform}-{arch}" / libname
    if not src.exists():
        error("no compiler and no prebuilt for this platform")
    verify_sha256(src)          # 或签名
    dst = ~/.vpo-hook/lib/libname
    copy(src, dst)
    return dst
```

要求：

- 本机编译成功时，**绝不**覆盖成本机产物
- 预编译库必须校验 hash/签名
- 失败时报出平台、架构、缺失目录，不要静默
- macOS 记录是否因 SIP/hardened runtime 无法注入
- 运行时 `run` 优先使用 `~/.vpo-hook/lib`，再兼容包内旧产物

---

## 7. CI 建议

```text
linux-x86_64  -> manylinux2014 container
linux-aarch64 -> native arm64 runner 或 qemu
darwin-arm64  -> GitHub Actions macos-14
darwin-x86_64 -> GitHub Actions macos-13 / cross build
```

每个产物都要：

- 生成 `SHA256SUMS`
- 跑 `readelf`/`otool` 检查
- 在对应环境跑 `LD_PRELOAD`/`DYLD_INSERT_LIBRARIES` smoke test
- 记录编译器、libc、SDK、构建时间

发布前跑：

```bash
python3 scripts/release.py --check
bash scripts/verify_linux.sh
bash scripts/verify_install.sh
```

---

## 8. 发布检查清单

- [ ] `prebuilt/` 四个平台目录齐全（至少 Linux x86_64 + macOS arm64）
- [ ] `SHA256SUMS` / 签名生成并校验
- [ ] `init` 本机编译优先 + 预编译 fallback
- [ ] 旧 glibc 容器验证通过
- [ ] macOS arm64/x86_64 验证通过
- [ ] `pip install ./release/py` 后 `import vpoh` 正常
- [ ] `npm install ./release/js` 后 `require('vpo-hook')` 正常
- [ ] `README` / `LICENSE` / `MANIFEST.in` / 包元数据补齐
- [ ] CI 复现上述步骤

---

## 9. 参考

- `LINUX_MIGRATION.md`：Linux 运行时迁移、同名符号、LFS 别名、验收步骤
- 已忽略的本地 `addition.md` 6.2：预编译原始草稿（不再 tracked）
- `Target.md`：平台策略、商业分层（本地保留，不再 tracked）
