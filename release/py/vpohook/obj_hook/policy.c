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

#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

    parse_list(getenv("VPO_DENY_PATHS"), &deny_paths, &deny_count, ':');
    parse_list(getenv("VPO_ALLOW_NETWORK"), &allow_network, &allow_count, ',');
    parse_list(getenv("VPO_HIGH_RISK_MARKERS"), &risk_markers, &risk_count, ':');

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

static const char *rewrite_for(const char *path) {
    if (!path || !*path) return NULL;
    for (size_t i = 0; i < deny_count; i++) {
        if (deny_paths[i] && match_path(path, deny_paths[i])) {
            if (i < rewrite_count && rewrite_paths[i]) {
                if (strcmp(path, deny_paths[i]) == 0) return rewrite_paths[i];
                static __thread char buf[PATH_MAX];
                snprintf(buf, sizeof(buf), "%s%s", rewrite_paths[i], path + strlen(deny_paths[i]));
                return buf;
            }
            return NULL;
        }
    }
    return NULL;
}

/* ---------------------------------------------------------------------------
 * 网络地址检查（allow_network 白名单，第一版支持 IP:port）
 * ------------------------------------------------------------------------- */
static int network_allowed(const struct sockaddr *addr, socklen_t addrlen) {
    if (!addr) return 1;          /* 无地址，放行 */
    if (allow_count == 0) return 1; /* 未配置白名单，放行 */

    char host[NI_MAXHOST], serv[NI_MAXSERV];
    if (getnameinfo(addr, addrlen, host, sizeof(host), serv, sizeof(serv),
                    NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
        return 1;                 /* 解析失败，放行 */
    }
    char ip_port[NI_MAXHOST + NI_MAXSERV + 2];
    snprintf(ip_port, sizeof(ip_port), "%s:%s", host, serv);

    for (size_t i = 0; i < allow_count; i++) {
        if (allow_network[i] && strcmp(allow_network[i], ip_port) == 0) return 1;
    }
    return 0;                     /* 不在白名单 */
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

/* ---------------------------------------------------------------------------
 * 入口
 * ------------------------------------------------------------------------- */
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
        const char *rw = rewrite_for(a->path);
        if (rw) action->rewrite = rw;
    }
    if (a->path2 && path_blocked(a->path2)) {
        action->allow = 0;
    }
    /* 网络检查：只针对主动外连（connect/sendto），不拦监听（bind）/接收（recvfrom） */
    if (a->addr && (strcmp(func, "connect") == 0 || strcmp(func, "sendto") == 0)
        && !network_allowed(a->addr, a->addrlen)) {
        action->allow = 0;
    }
    /* 数据标记检查：跳过 stdout/stderr(fd<=2)，只拦写文件/写网络等真正外泄 */
    if (a->buf && a->fd > 2 && buffer_has_marker(a->buf, a->buflen)) {
        action->allow = 0;
    }
    return 0;
}
