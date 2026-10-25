#include <node_api.h>
#include <fcntl.h>
#include <unistd.h>

static napi_value OpenFile(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value argv[1];
    napi_get_cb_info(env, info, &argc, argv, NULL, NULL);

    char path[256];
    size_t len;
    napi_get_value_string_utf8(env, argv[0], path, sizeof(path), &len);

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        napi_throw_error(env, NULL, "open failed");
        return NULL;
    }
    close(fd);
    return NULL;
}

static napi_value Init(napi_env env, napi_value exports) {
    napi_value fn;
    napi_create_function(env, "openFile", NAPI_AUTO_LENGTH, OpenFile, NULL, &fn);
    napi_set_named_property(env, exports, "openFile", fn);
    return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
