# Fuzzing

Fuzz tests use [libFuzzer](http://llvm.org/docs/LibFuzzer.html) to test the SAPI
API functions (with a few [exceptions](https://github.com/tpm2-software/tpm2-tss/blob/master/script/gen_fuzz.py#L177)).

Building fuzz tests can be enabled using the `--with-fuzzing=` option. For which
there are two possible values.

- [libfuzzer](#libfuzzer)
- [ossfuzz](#oss-fuzz)

## libFuzzer

libFuzzer tests can be built natively or using the docker `fuzzing` target.

### Natively

Build the fuzz tests by setting `--with-fuzzing=libfuzzer` and statically
linking to the fuzzing TCTI. Note that we build with source coverage (not to be confused with sanitizer coverage needed by libfuzzer), here. This flag impacts performance and is optional.

```bash
export GEN_FUZZ=1

./bootstrap
./configure \
  CC=clang \
  --enable-debug \
  --with-fuzzing=libfuzzer \
  --enable-code-coverage\
  --disable-esys \
  --disable-fapi \
  --enable-tcti-fuzzing \
  --disable-tcti-cmd \
  --disable-tcti-device\
  --disable-tcti-i2c-ftdi \
  --disable-tcti-libtpms\
  --disable-tcti-mssim \
  --disable-tcti-pcap\
  --disable-tcti-spi-ftdi \
  --disable-tcti-spi-ltt2go \
  --disable-tcti-spidev \
  --disable-tcti-start-sim \
  --disable-tcti-swtpm \
  --with-maxloglevel=none \
  --disable-shared

make -j $(nproc) check TESTS=""
```

Run the fuzz tests by executing any binary ending in `.fuzz` in `test/fuzz/`.

For example
```bash
test/fuzz/Tss2_Sys_EncryptDecrypt.fuzz
```

Pass libfuzzer options to customize the approach
```bash
# see test/fuzz/Tss2_Sys_EncryptDecrypt.fuzz -help=1
test/fuzz/Tss2_Sys_EncryptDecrypt.fuzz -max_total_time=20 -jobs=$(nproc) ./corpus
```

To inspect the source coverage
```bash
gcovr --gcov-executable "llvm-cov gcov" --html-details coverage.html
```

### Docker

Build the fuzz targets and check that they work by building the fuzz tests in a docker
container.

```bash
GEN_FUZZ=1 CC=clang docker run --rm -ti --cap-add=SYS_PTRACE --env-file .ci/docker.env -v $PWD:/workspace/tpm2-tss ghcr.io/tpm2-software/fedora-32 /bin/bash -c /workspace/tpm2-tss/.ci/docker.run
```

Run a fuzz target and mount a directory as a volume into the container where it
should store its findings should it produce any.

```bash
GEN_FUZZ=1 CC=clang docker run --rm -ti --cap-add=SYS_PTRACE --env-file .ci/docker.env -v $PWD:/workspace/tpm2-tss ghcr.io/tpm2-software/fedora-32

# cd /workspace/tpm2-tss/
# test/fuzz/Tss2_Sys_EncryptDecrypt.fuzz
```

## OSS Fuzz

OSS fuzz integration can be found under the
[tpm2-tss](https://github.com/google/oss-fuzz/tree/master/projects/tpm2-tss)
project in OSS Fuzz.

The `Dockerfile` there builds the dependencies. `build.sh` Runs the compilation
as seen under the `fuzzing` target of the `Dockerfile` in this repo, only
`--with-fuzzing=ossfuzz`.

## Hacking

Currently only fuzz targets for the System API have been implemented.

### TCTI

The fuzzing TCTI is used as a temporary storage location for the `Data` and
`Size` arguments of `LLVMFuzzerTestOneInput`.

For `_Complete` calls the TCTI uses `Data` and `Size` as the response buffer and
response size for `TSS2_TCTI_RECEIVE`.

### SAPI

Fuzz tests are generated via `script/gen_fuzz.py`.

Setting `GEN_FUZZ=1` when running `bootstrap` will run `script/gen_fuzz.py`.

```bash
GEN_FUZZ=1 ./bootstrap
```

`script/gen_fuzz.py` reads the SAPI header file and generates a fuzz target for
each `_Prepare` and `_Complete` call using similar templates.

For `_Prepare` calls the `fuzz_fill` function in the fuzzing TCTI will fill each
TPM2 structure used can copy from `LLVMFuzzerTestOneInput`'s `Data` into it.
