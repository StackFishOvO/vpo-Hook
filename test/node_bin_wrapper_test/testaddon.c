#include <node_api.h>
#include <fcntl.h>
#include <unistd.h>

static napi_value ReadFirst(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value argv[1];
    napi_get_cb_info(env, info, &argc, argv, NULL, NULL);

    char path[512];
    size_t len;
    napi_get_value_string_utf8(env, argv[0], path, sizeof(path), &len);

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        napi_throw_error(env, NULL, "open failed");
        return NULL;
    }
    char buf[64];
    ssize_t n = read(fd, buf, 40);
    close(fd);
    if (n < 0) n = 0;
    napi_value out;
    napi_create_string_utf8(env, buf, (size_t)n, &out);
    return out;
}

static napi_value Init(napi_env env, napi_value exports) {
    napi_value fn;
    napi_create_function(env, "readFirst", NAPI_AUTO_LENGTH, ReadFirst, NULL, &fn);
    napi_set_named_property(env, exports, "readFirst", fn);
    return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
