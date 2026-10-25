#include <Python.h>
#include <fcntl.h>
#include <unistd.h>

static PyObject* test_open_file(PyObject* self, PyObject* args) {
    const char* path;
    if (!PyArg_ParseTuple(args, "s", &path)) return NULL;

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return PyErr_SetFromErrno(PyExc_OSError);
    }
    close(fd);
    Py_RETURN_NONE;
}

static PyMethodDef Methods[] = {
    {"open_file", test_open_file, METH_VARARGS, "test"},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef moduledef = {
    PyModuleDef_HEAD_INIT, "testmod", NULL, -1, Methods
};

PyMODINIT_FUNC PyInit_testmod(void) {
    return PyModule_Create(&moduledef);
}