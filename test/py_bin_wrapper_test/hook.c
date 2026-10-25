#include <stdio.h>
#include <fcntl.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <string.h>

typedef int (*open_t)(const char *, int, ...);
typedef int (*__open_t)(const char *, int, mode_t);

static int is_blocked(const char *path) {
    return path && strcmp(path, "/etc/hosts") == 0;
}

int my_open(const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }

    if (is_blocked(path)) {
        fprintf(stderr, "[HOOK] BLOCKED: %s\n", path);
        return -1;
    }

    static __open_t real_open = NULL;
    if (!real_open) {
        real_open = (__open_t)dlsym(RTLD_DEFAULT, "__open");
    }
    return real_open(path, flags, mode);
}

#define DYLD_INTERPOSE(_replacement, _original) \
    __attribute__((used)) static struct { \
        const void* replacement; \
        const void* original; \
    } _interpose_##_original \
    __attribute__((section("__DATA,__interpose"))) = { \
        (const void*)(unsigned long)&_replacement, \
        (const void*)(unsigned long)&_original \
    };

DYLD_INTERPOSE(my_open, open)
