"""Compile the required proof-of-work extension during installation."""

from Cython.Build import cythonize
from setuptools import Extension, setup

setup(
    ext_modules=cythonize(
        [Extension("byse_resolver._byse_pow", ["src/byse_resolver/_byse_pow.pyx"])],
        build_dir="build/cython",
        compiler_directives={"language_level": 3},
    ),
)
