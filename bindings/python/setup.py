from setuptools import setup

setup(
    name="pytpm2tss",
    version="0.1",
    description="Binding for tpm2tss (Esys and types for now",
    url="https://github.com/tpm2-software/tpm2-tss",
    author="Andreas Fuchs",
    setup_requires=["cffi>=1.0.0"],
    cffi_modules=["pytpm2tss/libesys_build.py:ffibuilder"],
    install_requires=["cffi>=1.0.0"],
)
