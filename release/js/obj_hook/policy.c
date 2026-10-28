/*
 * policy.c -- VPO-Hook 二进制层策略引擎。
 *
 * 配置通过「环境变量」传入（读文件会走被拦截的 open/read 导致递归），启动器负责
 * 把 config.yaml 展开成：
 *   VPO_DENY_PATHS        /etc/passwd:/Users/xxx/.ssh:...
 *   VPO_REWRITE_MAP       /etc/passwd=/Users/xxx/.vpo-hook/honeypot/passwd:...
 *   VPO_ALLOW_NETWORK     1.2.3.4:443:...
 *   VPO_HIGH_RISK_MARKERS token:secret:password
 *
 * 动作模型：只做 ALLOW / DENY / REWRITE，无 ASK（ASK 属于名文层）。
 */

#include "vpo_hook.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/uio.h>

#if defined(__APPLE__)
#define VPO_PRELOAD_KEY "DYLD_INSERT_LIBRARIES"
#else
#define VPO_PRELOAD_KEY "LD_PRELOAD"
#endif

/* ---------------------------------------------------------------------------
 * 内存缓存
 * ------------------------------------------------------------------------- */
static char **deny_paths = NULL;
static size_t deny_count = 0;
static char **rewrite_paths = NULL;   /* 与 deny_paths 对应，可 NULL */
static size_t rewrite_count = 0;
static char **allow_network = NULL;   /* 网络白名单：IP:port */
static size_t allow_count = 0;
static char **risk_markers = NULL;    /* 数据高危标记 */
static size_t risk_count = 0;
static int loaded = 0;

/* 简单安全组（profile: simple）运行时字段 */
static char *env_root = NULL;         /* VPO_ENV_ROOT：信任区根目录 */
static char **runtime_dirs = NULL;    /* VPO_RUNTIME_DIRS：系统只读目录 */
static size_t runtime_count = 0;
static char **extra_paths = NULL;     /* VPO_EXTRA_PATHS：额外授权路径 */
static size_t extra_count = 0;
static char **network_blocklist = NULL; /* VPO_NETWORK_BLOCKLIST：可疑 host/ip */
static size_t blocklist_count = 0;
static char **exec_allow = NULL;      /* VPO_EXEC_ALLOW：可执行文件 */
static size_t exec_allow_count = 0;
static int network_mode = -1;         /* -1 旧行为, 0 off, 1 internet, 2 allowlist */
static int exec_mode = -1;            /* -1 旧行为, 0 off, 1 allowlist, 2 shell */
static int data_mode = 0;             /* 0 block（默认拒绝）, 1 honeypot（外发数据重写成蜜罐） */

/* 拒绝审计：绕过自身 wrapper，用真实 open/write 追加到 denials.log */
static int denials_fd = -1;

/* ---------------------------------------------------------------------------
 * P0-B：constructor 时缓存原始环境变量。
 *
 * 不能等到 execve 时再 getenv()：guest 可以先 unsetenv() 再 execve，从而把
 * 策略环境清空。这里在库加载时（constructor）就复制一份，后续只用这份快照。
 * ------------------------------------------------------------------------- */
static char *cached_deny_paths = NULL;
static char *cached_rewrite_map = NULL;
static char *cached_allow_network = NULL;
static char *cached_risk_markers = NULL;
static char *cached_hook_config = NULL;
static char *cached_hook_py_api = NULL;
static char *cached_hook_js_api = NULL;
static char *cached_audit_classes = NULL;
static char *cached_audit_log = NULL;
static char *cached_pythonpath_prefix = NULL;
static char *cached_node_options_prefix = NULL;
static char *cached_preload = NULL;
static int env_cached = 0;

static char *env_dup(const char *name) {
    const char *v = getenv(name);
    if (!v || !*v) return NULL;
    return strdup(v);
}

static int set_or_unset_env(const char *key, const char *value) {
    if (value) return setenv(key, value, 1);
    return unsetenv(key);
}

static void load_policy(void);
static char *vpo_merge_prefix(const char *prefix, char sep, const char *existing);

static void cache_env(void) {
    if (env_cached) return;
    env_cached = 1;

    cached_deny_paths = env_dup("VPO_DENY_PATHS");
    cached_rewrite_map = env_dup("VPO_REWRITE_MAP");
    cached_allow_network = env_dup("VPO_ALLOW_NETWORK");
    cached_risk_markers = env_dup("VPO_HIGH_RISK_MARKERS");
    cached_hook_config = env_dup("VPO_HOOK_CONFIG");
    cached_hook_py_api = env_dup("VPO_HOOK_PY_API");
    cached_hook_js_api = env_dup("VPO_HOOK_JS_API");
    cached_audit_classes = env_dup("VPO_AUDIT_CLASSES");
    cached_audit_log = env_dup("VPO_AUDIT_LOG");
    cached_pythonpath_prefix = env_dup("VPO_PYTHONPATH");
    cached_node_options_prefix = env_dup("VPO_NODE_OPTIONS");
    cached_preload = env_dup(VPO_PRELOAD_KEY);
}

/* 用真实 open 打开拒绝日志（绕过我们自己的 open wrapper，避免递归） */
static void open_denials_log(void) {
    const char *path = getenv("VPO_DENIALS_LOG");
    if (!path || !*path) return;
    typedef int (*open_fn)(const char *, int, ...);
    open_fn fn = (open_fn)dlsym(RTLD_NEXT, "open");
    if (!fn) fn = (open_fn)dlsym(RTLD_NEXT, "open64");
    if (!fn) return;
    denials_fd = fn(path, O_WRONLY | O_CREAT | O_APPEND, 0600);
}

/* 追加一条拒绝记录，用真实 write 绕过自身 wrapper */
static void log_denial(const char *func, const char *path) {
    if (denials_fd < 0) return;
    typedef ssize_t (*write_fn)(int, const void *, size_t);
    static write_fn wf = NULL;
    if (!wf) wf = (write_fn)dlsym(RTLD_NEXT, "write");
    if (!wf) return;
    char buf[2048];
    int n = snprintf(buf, sizeof(buf),
                     "{\"ts\":%lld,\"func\":\"%s\",\"path\":\"%s\"}\n",
                     (long long)time(NULL),
                     func ? func : "",
                     path ? path : "");
    if (n > 0 && (size_t)n < sizeof(buf)) {
        wf(denials_fd, buf, (size_t)n);
    }
}

/* 把 constructor 缓存的环境变量写回当前进程 environ。 */
int vpo_reinject_environ(void) {
    load_policy();

    if (set_or_unset_env("VPO_HOOK_CONFIG", cached_hook_config) != 0) return -1;
    if (set_or_unset_env("VPO_DENY_PATHS", cached_deny_paths) != 0) return -1;
    if (set_or_unset_env("VPO_REWRITE_MAP", cached_rewrite_map) != 0) return -1;
    if (set_or_unset_env("VPO_ALLOW_NETWORK", cached_allow_network) != 0) return -1;
    if (set_or_unset_env("VPO_HIGH_RISK_MARKERS", cached_risk_markers) != 0) return -1;
    if (set_or_unset_env("VPO_HOOK_PY_API", cached_hook_py_api) != 0) return -1;
    if (set_or_unset_env("VPO_HOOK_JS_API", cached_hook_js_api) != 0) return -1;
    if (set_or_unset_env("VPO_AUDIT_CLASSES", cached_audit_classes) != 0) return -1;
    if (set_or_unset_env("VPO_AUDIT_LOG", cached_audit_log) != 0) return -1;
    if (set_or_unset_env("VPO_PYTHONPATH", cached_pythonpath_prefix) != 0) return -1;
    if (set_or_unset_env("VPO_NODE_OPTIONS", cached_node_options_prefix) != 0) return -1;

    if (cached_pythonpath_prefix) {
        char *merged = vpo_merge_prefix(cached_pythonpath_prefix, ':', getenv("PYTHONPATH"));
        if (!merged) return -1;
        int rc = setenv("PYTHONPATH", merged, 1);
        free(merged);
        if (rc != 0) return -1;
    }
    if (cached_node_options_prefix) {
        char *merged = vpo_merge_prefix(cached_node_options_prefix, ' ', getenv("NODE_OPTIONS"));
        if (!merged) return -1;
        int rc = setenv("NODE_OPTIONS", merged, 1);
        free(merged);
        if (rc != 0) return -1;
    }
    if (cached_preload) {
        char *merged = vpo_merge_prefix(cached_preload, ':', getenv(VPO_PRELOAD_KEY));
        if (!merged) return -1;
        int rc = setenv(VPO_PRELOAD_KEY, merged, 1);
        free(merged);
        if (rc != 0) return -1;
    }
    return 0;
}

/* 合并前缀：VPO 的值放前面；若 existing 已包含 prefix，则不重复添加。 */
static char *vpo_merge_prefix(const char *prefix, char sep, const char *existing) {
    if (!prefix || !*prefix) return existing ? strdup(existing) : NULL;
    if (!existing || !*existing) return strdup(prefix);
    if (strstr(existing, prefix)) return strdup(existing);
    size_t n = strlen(prefix) + 1 + strlen(existing) + 1;
    char *out = malloc(n);
    if (!out) return NULL;
    snprintf(out, n, "%s%c%s", prefix, sep, existing);
    return out;
}

static int env_key_is(const char *entry, const char *key) {
    if (!entry || !key) return 0;
    size_t n = strlen(key);
    size_t el = strlen(entry);
    return el > n && entry[n] == '=' && memcmp(entry, key, n) == 0;
}

static const char *env_entry_value(const char *entry) {
    const char *eq = entry ? strchr(entry, '=') : NULL;
    return eq ? eq + 1 : NULL;
}

static int env_is_vpo_key(const char *entry) {
    static const char *const keys[] = {
        "VPO_HOOK_CONFIG", "VPO_DENY_PATHS", "VPO_REWRITE_MAP",
        "VPO_ALLOW_NETWORK", "VPO_HIGH_RISK_MARKERS", "VPO_HOOK_PY_API",
        "VPO_HOOK_JS_API", "VPO_AUDIT_CLASSES", "VPO_AUDIT_LOG",
        "VPO_PYTHONPATH", "VPO_NODE_OPTIONS", NULL
    };
    for (size_t i = 0; keys[i]; i++) {
        if (env_key_is(entry, keys[i])) return 1;
    }
    return 0;
}

static const char *env_find(char *const envp[], const char *key) {
    if (!envp) return NULL;
    for (size_t i = 0; envp[i]; i++) {
        if (env_key_is(envp[i], key)) return env_entry_value(envp[i]);
    }
    return NULL;
}

static int env_add(char **out, size_t *idx, const char *key, const char *value) {
    if (!value) return 0;
    size_t n = strlen(key) + 1 + strlen(value) + 1;
    char *s = malloc(n);
    if (!s) return -1;
    snprintf(s, n, "%s=%s", key, value);
    out[(*idx)++] = s;
    return 0;
}

void vpo_envp_free(char **envp) {
    if (!envp) return;
    for (size_t i = 0; envp[i]; i++) free(envp[i]);
    free(envp);
}

char **vpo_envp_merge(char *const envp[]) {
    load_policy();

    size_t orig_count = 0;
    if (envp) {
        while (envp[orig_count]) orig_count++;
    }

    /* 原 envp + 12 个 VPO 键 + PYTHONPATH/NODE_OPTIONS/LD_PRELOAD + NULL */
    char **out = calloc(orig_count + 20, sizeof(char *));
    if (!out) return NULL;
    size_t idx = 0;

    for (size_t i = 0; i < orig_count; i++) {
        const char *entry = envp[i];
        if (env_is_vpo_key(entry)
            || env_key_is(entry, "PYTHONPATH")
            || env_key_is(entry, "NODE_OPTIONS")
            || env_key_is(entry, VPO_PRELOAD_KEY)) {
            continue;
        }
        char *copy = strdup(entry);
        if (!copy) {
            vpo_envp_free(out);
            return NULL;
        }
        out[idx++] = copy;
    }

    if (env_add(out, &idx, "VPO_HOOK_CONFIG", cached_hook_config) != 0
        || env_add(out, &idx, "VPO_DENY_PATHS", cached_deny_paths) != 0
        || env_add(out, &idx, "VPO_REWRITE_MAP", cached_rewrite_map) != 0
        || env_add(out, &idx, "VPO_ALLOW_NETWORK", cached_allow_network) != 0
        || env_add(out, &idx, "VPO_HIGH_RISK_MARKERS", cached_risk_markers) != 0
        || env_add(out, &idx, "VPO_HOOK_PY_API", cached_hook_py_api) != 0
        || env_add(out, &idx, "VPO_HOOK_JS_API", cached_hook_js_api) != 0
        || env_add(out, &idx, "VPO_AUDIT_CLASSES", cached_audit_classes) != 0
        || env_add(out, &idx, "VPO_AUDIT_LOG", cached_audit_log) != 0
        || env_add(out, &idx, "VPO_PYTHONPATH", cached_pythonpath_prefix) != 0
        || env_add(out, &idx, "VPO_NODE_OPTIONS", cached_node_options_prefix) != 0) {
        vpo_envp_free(out);
        return NULL;
    }

    if (cached_pythonpath_prefix) {
        char *merged = vpo_merge_prefix(cached_pythonpath_prefix, ':', env_find(envp, "PYTHONPATH"));
        if (!merged || env_add(out, &idx, "PYTHONPATH", merged) != 0) {
            free(merged);
            vpo_envp_free(out);
            return NULL;
        }
        free(merged);
    }
    if (cached_node_options_prefix) {
        char *merged = vpo_merge_prefix(cached_node_options_prefix, ' ', env_find(envp, "NODE_OPTIONS"));
        if (!merged || env_add(out, &idx, "NODE_OPTIONS", merged) != 0) {
            free(merged);
            vpo_envp_free(out);
            return NULL;
        }
        free(merged);
    }
    if (cached_preload) {
        char *merged = vpo_merge_prefix(cached_preload, ':', env_find(envp, VPO_PRELOAD_KEY));
        if (!merged || env_add(out, &idx, VPO_PRELOAD_KEY, merged) != 0) {
            free(merged);
            vpo_envp_free(out);
            return NULL;
        }
        free(merged);
    }
    return out;
}

/* 解析分隔符分隔的字符串列表（sep 指定分隔符，allow_network 用逗号因条目含冒号） */
static void parse_list(const char *raw, char ***out, size_t *out_count, char sep) {
    if (!raw || !*raw) return;
    char *copy = strdup(raw);
    if (!copy) return;
    size_t n = 1;
    for (const char *p = copy; *p; p++) {
        if (*p == sep) n++;
    }
    char **arr = calloc(n, sizeof(char *));
    if (!arr) {
        free(copy);
        return;
    }
    char sep_str[2] = {sep, '\0'};
    size_t i = 0;
    char *save = NULL;
    for (char *tok = strtok_r(copy, sep_str, &save);
         tok != NULL && i < n;
         tok = strtok_r(NULL, sep_str, &save)) {
        if (*tok) arr[i++] = strdup(tok);
    }
    *out = arr;
    *out_count = i;
    free(copy);
}

static void load_policy(void) {
    if (loaded) return;
    loaded = 1;
    cache_env();
    open_denials_log();

    parse_list(getenv("VPO_DENY_PATHS"), &deny_paths, &deny_count, ':');
    parse_list(getenv("VPO_ALLOW_NETWORK"), &allow_network, &allow_count, ',');
    parse_list(getenv("VPO_HIGH_RISK_MARKERS"), &risk_markers, &risk_count, ':');

    /* 简单安全组字段（无则保持旧行为） */
    env_root = env_dup("VPO_ENV_ROOT");
    parse_list(getenv("VPO_RUNTIME_DIRS"), &runtime_dirs, &runtime_count, ':');
    parse_list(getenv("VPO_EXTRA_PATHS"), &extra_paths, &extra_count, ':');
    parse_list(getenv("VPO_NETWORK_BLOCKLIST"), &network_blocklist, &blocklist_count, ',');
    parse_list(getenv("VPO_EXEC_ALLOW"), &exec_allow, &exec_allow_count, ':');
    const char *nm = getenv("VPO_NETWORK_MODE");
    if (nm) {
        if (strcmp(nm, "off") == 0) network_mode = 0;
        else if (strcmp(nm, "internet") == 0) network_mode = 1;
        else if (strcmp(nm, "allowlist") == 0) network_mode = 2;
    }
    const char *em = getenv("VPO_EXEC_MODE");
    if (em) {
        if (strcmp(em, "off") == 0) exec_mode = 0;
        else if (strcmp(em, "allowlist") == 0) exec_mode = 1;
        else if (strcmp(em, "shell") == 0) exec_mode = 2;
    }
    const char *dm = getenv("VPO_DATA_MODE");
    if (dm && strcmp(dm, "honeypot") == 0) data_mode = 1;

    /* rewrite 映射：deny=蜜罐，冒号分隔 */
    const char *raw_map = getenv("VPO_REWRITE_MAP");
    if (raw_map && *raw_map && deny_count > 0) {
        rewrite_paths = calloc(deny_count, sizeof(char *));
        rewrite_count = deny_count;
        char *copy = strdup(raw_map);
        if (copy) {
            char *save = NULL;
            for (char *tok = strtok_r(copy, ":", &save);
                 tok != NULL;
                 tok = strtok_r(NULL, ":", &save)) {
                char *eq = strchr(tok, '=');
                if (!eq) continue;
                *eq = '\0';
                for (size_t i = 0; i < deny_count; i++) {
                    if (deny_paths[i] && strcmp(deny_paths[i], tok) == 0) {
                        rewrite_paths[i] = strdup(eq + 1);
                        break;
                    }
                }
            }
            free(copy);
        }
    }
}

/* ---------------------------------------------------------------------------
 * 路径检查
 * ------------------------------------------------------------------------- */
static int match_path(const char *path, const char *d) {
    size_t dl = strlen(d);
    if (strcmp(path, d) == 0) return 1;
    if (strncmp(path, d, dl) == 0 && path[dl] == '/') return 1;
    return 0;
}

static int path_blocked(const char *path) {
    if (!path || !*path) return 0;
    for (size_t i = 0; i < deny_count; i++) {
        if (deny_paths[i] && match_path(path, deny_paths[i])) return 1;
    }
    return 0;
}

static void rewrite_for(const char *path, char *out_buf, size_t out_len, const char **out) {
    *out = NULL;
    if (!path || !*path) return;
    for (size_t i = 0; i < deny_count; i++) {
        if (deny_paths[i] && match_path(path, deny_paths[i])) {
            if (i < rewrite_count && rewrite_paths[i]) {
                if (strcmp(path, deny_paths[i]) == 0) {
                    *out = rewrite_paths[i];
                    return;
                }
                snprintf(out_buf, out_len, "%s%s", rewrite_paths[i], path + strlen(deny_paths[i]));
                *out = out_buf;
                return;
            }
            return;
        }
    }
}

/* ---------------------------------------------------------------------------
 * 网络地址检查
 * ------------------------------------------------------------------------- */
static int ip4_private(unsigned a, unsigned b, unsigned c, unsigned d) {
    if (a == 10) return 1;
    if (a == 172 && b >= 16 && b <= 31) return 1;
    if (a == 192 && b == 168) return 1;
    if (a == 127) return 1;           /* loopback 一视同仁，不隐式放行 */
    if (a == 169 && b == 254) return 1; /* 含云 metadata */
    if (a == 0) return 1;
    if (a == 100 && b >= 64 && b <= 127) return 1; /* CGNAT */
    if (a >= 224) return 1;           /* 组播/保留 */
    return 0;
}

static int host_is_private(const char *host) {
    unsigned a = 0, b = 0, c = 0, d = 0;
    if (sscanf(host, "%u.%u.%u.%u", &a, &b, &c, &d) == 4
        && a <= 255 && b <= 255 && c <= 255 && d <= 255) {
        return ip4_private(a, b, c, d);
    }
    if (strchr(host, ':')) {
        if (strcmp(host, "::1") == 0) return 1;
        if (strncmp(host, "fc", 2) == 0 || strncmp(host, "fd", 2) == 0) return 1;
        if (strncmp(host, "fe8", 3) == 0 || strncmp(host, "fe9", 3) == 0
            || strncmp(host, "fea", 3) == 0 || strncmp(host, "feb", 3) == 0) return 1;
    }
    return 0;
}

static int blocklisted(const char *host, const char *ip_port) {
    for (size_t i = 0; i < blocklist_count; i++) {
        const char *b = network_blocklist[i];
        if (!b) continue;
        if (strcmp(b, host) == 0) return 1;
        if (ip_port && strcmp(b, ip_port) == 0) return 1;
    }
    return 0;
}

static int network_allowed(const struct sockaddr *addr, socklen_t addrlen) {
    if (!addr) return 1;
    /* 旧行为：没配置白名单就放行；简单安全组显式三态才收紧 */
    if (network_mode == -1 && allow_count == 0) return 1;

    char host[NI_MAXHOST], serv[NI_MAXSERV];
    if (getnameinfo(addr, addrlen, host, sizeof(host), serv, sizeof(serv),
                    NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
        return network_mode == -1 ? 1 : 0;
    }
    char ip_port[NI_MAXHOST + NI_MAXSERV + 2];
    snprintf(ip_port, sizeof(ip_port), "%s:%s", host, serv);

    if (network_mode == -1) { /* 旧行为：IP:port 白名单 */
        for (size_t i = 0; i < allow_count; i++) {
            if (allow_network[i] && strcmp(allow_network[i], ip_port) == 0) return 1;
        }
        return 0;
    }

    if (network_mode == 0) return 0; /* off */

    if (blocklisted(host, ip_port)) return 0;

    if (network_mode == 1) { /* internet：只放公网 80/443/53 */
        if (host_is_private(host)) return 0;
        if (strcmp(serv, "80") != 0 && strcmp(serv, "443") != 0
            && strcmp(serv, "53") != 0) return 0;
        return 1;
    }

    /* allowlist：IP:port 或 host 精确匹配 */
    for (size_t i = 0; i < allow_count; i++) {
        if (!allow_network[i]) continue;
        if (strcmp(allow_network[i], ip_port) == 0) return 1;
        if (strcmp(allow_network[i], host) == 0) return 1;
    }
    return 0;
}

/* ---------------------------------------------------------------------------
 * 数据标记检查（buffer 内容扫描）
 * ------------------------------------------------------------------------- */
#define VPO_MAX_SCAN 4096

/*
 * 【ML 空位】当前实现是简单子串匹配（扫描 buf 前 VPO_MAX_SCAN 字节，找
 * high_risk_markers 子串）。
 *
 * 未来可在此处替换为小型 ML 模型判断：输入 buffer + 长度，输出 1(含敏感数据)/0(安全)。
 * 模型可放在蜜罐运维脚本或独立二进制中，通过环境变量 / 共享内存 / IPC 传结果，
 * 函数签名保持不变（buffer_has_marker 的输入输出不变），上层 vpo_check 无需改动。
 */
static int buffer_has_marker(const void *buf, size_t buflen) {
    if (!buf || buflen == 0 || risk_count == 0) return 0;
    size_t scan = buflen < VPO_MAX_SCAN ? buflen : VPO_MAX_SCAN;
    const char *p = (const char *)buf;
    for (size_t i = 0; i < risk_count; i++) {
        const char *m = risk_markers[i];
        size_t ml = strlen(m);
        if (ml == 0 || ml > scan) continue;
        for (size_t j = 0; j + ml <= scan; j++) {
            if (memcmp(p + j, m, ml) == 0) return 1;
        }
    }
    return 0;
}

/* 把 buffer 里的敏感标记替换成 HONEYPOT，输出到 out（最多 out_cap-1 字节，\0 结尾）。 */
static void redact_buffer(const void *buf, size_t buflen, char *out, size_t out_cap, size_t *out_len) {
    const char *p = (const char *)buf;
    size_t o = 0;
    size_t i = 0;
    while (i < buflen && o + 1 < out_cap) {
        int matched = 0;
        for (size_t m = 0; m < risk_count; m++) {
            size_t ml = strlen(risk_markers[m]);
            if (ml == 0 || i + ml > buflen) continue;
            if (memcmp(p + i, risk_markers[m], ml) == 0) {
                const char *hp = "HONEYPOT";
                size_t hl = strlen(hp);
                if (o + hl >= out_cap) break;
                memcpy(out + o, hp, hl);
                o += hl;
                i += ml;
                matched = 1;
                break;
            }
        }
        if (!matched) {
            out[o++] = p[i++];
        }
    }
    out[o] = '\0';
    *out_len = o;
}

/* 就地脱敏：把 buffer 里的敏感标记逐字节替换成 "HONEYPOT"（重复/截断到标记长度，保持总长度不变）。 */
static void redact_inplace(char *p, size_t buflen) {
    const char *hp = "HONEYPOT";
    size_t hl = strlen(hp);
    size_t i = 0;
    while (i < buflen) {
        int matched = 0;
        for (size_t m = 0; m < risk_count; m++) {
            size_t ml = strlen(risk_markers[m]);
            if (ml == 0 || i + ml > buflen) continue;
            if (memcmp(p + i, risk_markers[m], ml) == 0) {
                for (size_t k = 0; k < ml; k++) p[i + k] = hp[k % hl];
                i += ml;
                matched = 1;
                break;
            }
        }
        if (!matched) i++;
    }
}

static int iovec_has_marker(const struct iovec *iov, int cnt) {
    for (int i = 0; i < cnt; i++) {
        if (buffer_has_marker(iov[i].iov_base, iov[i].iov_len)) return 1;
    }
    return 0;
}

static void redact_iovec(struct iovec *iov, int cnt) {
    for (int i = 0; i < cnt; i++) {
        redact_inplace((char *)iov[i].iov_base, iov[i].iov_len);
    }
}

/* ---------------------------------------------------------------------------
 * 入口
 * ------------------------------------------------------------------------- */
static int is_exec_func(const char *func) {
    static const char *const names[] = {
        "execve", "execv", "execvp", "posix_spawn", "posix_spawnp", NULL
    };
    for (size_t i = 0; names[i]; i++) {
        if (strcmp(func, names[i]) == 0) return 1;
    }
    return 0;
}

static int exec_allowed(const char *path) {
    if (exec_mode == -1) return 1;
    if (exec_mode == 2) return 1; /* shell */
    if (exec_mode == 0) return 0; /* off */
    if (!path || !*path) return 0;
    for (size_t i = 0; i < exec_allow_count; i++) {
        if (exec_allow[i] && strcmp(exec_allow[i], path) == 0) return 1;
    }
    return 0;
}

static int is_file_path_func(const char *func) {
    static const char *const names[] = {
        "open", "open64", "openat", "openat64", "fopen", "fopen64",
        "unlink", "unlinkat", "rename", "renameat", "mkdir", "rmdir", "dlopen",
        NULL
    };
    for (size_t i = 0; names[i]; i++) {
        if (strcmp(func, names[i]) == 0) return 1;
    }
    return 0;
}

static int path_in_scope(const char *path) {
    if (!env_root) return 1;
    if (!path || !*path) return 1;
    if (match_path(path, env_root)) return 1;
    for (size_t i = 0; i < runtime_count; i++) {
        if (runtime_dirs[i] && match_path(path, runtime_dirs[i])) return 1;
    }
    for (size_t i = 0; i < extra_count; i++) {
        if (extra_paths[i] && match_path(path, extra_paths[i])) return 1;
    }
    return 0;
}

__attribute__((constructor))
static void vpo_hook_constructor(void) {
    /* 在 guest 代码运行前缓存策略环境，防止后续 unsetenv 清空。 */
    load_policy();
}

int vpo_check(const char *func, void *args, vpo_action *action) {
    load_policy();

    if (action == NULL) return 0;

    vpo_args *a = (vpo_args *)args;
    if (a == NULL) return 0;

    if (a->path && path_blocked(a->path)) {
        action->allow = 0;
        const char *rw = NULL;
        rewrite_for(a->path, action->rewrite_buf, sizeof(action->rewrite_buf), &rw);
        if (rw) action->rewrite = rw;
    }
    if (a->path2 && path_blocked(a->path2)) {
        action->allow = 0;
    }
    /* 简单安全组：文件路径限定在 env_root / runtime / extra 内 */
    if (a->path && is_file_path_func(func) && !path_in_scope(a->path)) {
        action->allow = 0;
    }
    /* 简单安全组：exec 模式 */
    if (is_exec_func(func) && !exec_allowed(a->path)) {
        action->allow = 0;
    }
    /* 网络检查：只针对主动外连（connect/sendto），不拦监听（bind）/接收（recvfrom） */
    if (a->addr && (strcmp(func, "connect") == 0 || strcmp(func, "sendto") == 0)
        && !network_allowed(a->addr, a->addrlen)) {
        action->allow = 0;
    }
    /* 数据标记检查：跳过 stdout/stderr(fd<=2)，只拦写文件/写网络等真正外泄 */
    if (a->buf && a->fd > 2) {
        int has = a->iovec
            ? iovec_has_marker((const struct iovec *)a->buf, (int)a->buflen)
            : buffer_has_marker(a->buf, a->buflen);
        if (has) {
            if (data_mode == 1) {
                if (a->iovec) {
                    redact_iovec((struct iovec *)a->buf, (int)a->buflen);
                } else {
                    size_t olen = 0;
                    redact_buffer(a->buf, a->buflen, action->data_buf, sizeof(action->data_buf), &olen);
                    action->data_rewrite = action->data_buf;
                    action->data_rewrite_len = olen;
                }
            } else {
                action->allow = 0;
            }
        }
    }
    if (!action->allow) {
        log_denial(func, a->path);
    }
    return 0;
}
