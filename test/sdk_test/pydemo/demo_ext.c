/* SDK 测试用的最小 C 扩展：用 fopen64 读文件，供 nm 扫描 + 二进制 hook 验证 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>

char *read_first(const char *path) {
    FILE *f = fopen64(path, "r");
    if (!f) return "";
    static char buf[64];
    size_t n = fread(buf, 1, 40, f);
    buf[n] = 0;
    fclose(f);
    return buf;
}
