/*
 * vpo_hook.h -- 二进制 hook 的策略引擎 ABI 定义。
 *
 * wrapper.c（自动生成）和策略引擎（policy.c）共用此头文件，保证 vpo_action /
 * vpo_args 结构与 vpo_check 签名一致。
 */
#ifndef VPO_HOOK_H
#define VPO_HOOK_H

#include <limits.h>
#include <stddef.h>
#include <sys/socket.h>   /* socklen_t / struct sockaddr */

/*
 * 二进制层动作模型：只允许 ALLOW / DENY / REWRITE 三种，禁止 ASK（申请权限）。
 *
 * 原因：二进制 hook 位于 libc 出口，open/read/write 等调用极其频繁，若在 C 层做
 * ASK（同步询问宿主）会严重阻塞，且 C 层无法方便地做 IPC。因此：
 *   - 二进制层（policy.c）只做：放行(allow=1) / 拒绝(allow=0) / 改写(rewrite)。
 *   - ASK（申请权限）只属于名文层（接口级，调用频率低，可走 IPC）。
 */
typedef struct {
    int allow;              /* 1 = 放行，0 = 拒绝 */
    const char *rewrite;    /* rewrite_on_deny 时改写的新路径（Phase 3b） */
    char rewrite_buf[PATH_MAX]; /* rewrite 子路径拼接缓冲，随本结构体生命周期，消除隐式契约 */
    const void *data_rewrite;   /* 数据重写：指向 data_buf（外发消息 → 蜜罐） */
    size_t data_rewrite_len;    /* data_rewrite 的有效长度 */
    char data_buf[4096];        /* 数据重写缓冲 */
} vpo_action;

typedef struct {
    const char *path;              /* 路径类参数（open 的 pathname 等） */
    const char *path2;             /* 第二个路径参数（rename 的 newpath 等） */
    const struct sockaddr *addr;   /* 网络地址 */
    socklen_t addrlen;
    const void *buf;               /* 数据缓冲 */
    size_t buflen;
    int fd;                        /* 文件描述符（write/sendto 的 fd/sockfd） */
    int iovec;                     /* 1 = buf 是 iovec 数组（writev），0 = 单块缓冲 */
} vpo_args;

/*
 * 策略引擎入口。
 *   func   : 被拦截的函数名（"open"/"connect"/...）
 *   args   : 指向 vpo_args（wrapper 打包的参数），可为 NULL
 *   action : 输出，策略引擎填写 allow/rewrite
 * 返回 0。
 */
int vpo_check(const char *func, void *args, vpo_action *action);

/*
 * P0-B：子进程环境继承。
 *
 * vpo_envp_merge() 用 constructor 时缓存的 VPO_* / LD_PRELOAD（macOS 为
 * DYLD_INSERT_LIBRARIES）/ PYTHONPATH / NODE_OPTIONS 构造一个新的 envp。
 * 返回值是 malloc 出来的数组，调用方必须用 vpo_envp_free() 释放；数组里的
 * 字符串也归 vpo_envp_free() 释放。返回 NULL 表示分配失败。
 *
 * 注意：这里读的是 constructor 缓存的快照，不是运行时 getenv()，否则 guest
 * 可以先 unsetenv() 再 execve 逃逸。
 */
char **vpo_envp_merge(char *const envp[]);
void vpo_envp_free(char **envp);

/*
 * 把 constructor 缓存的环境变量重新写回当前进程 environ。
 * 用于 execv/execvp/system/popen 这类不接收显式 envp、只读 environ 的接口。
 * 返回 0 成功，-1 失败（errno = ENOMEM）。
 */
int vpo_reinject_environ(void);

#endif /* VPO_HOOK_H */
