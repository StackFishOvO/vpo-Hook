# setup.py
from setuptools import setup, Extension
setup(
    name="testmod",
    ext_modules=[Extension("testmod", ["testmod.c"])],
)