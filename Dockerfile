FROM tpm2software/tpm2-tss AS base

COPY . /tmp/tpm2-tss/
WORKDIR /tmp/tpm2-tss
ENV LD_LIBRARY_PATH /usr/local/lib

# Install libjson-c
RUN apt-get update && apt-get install -y --no-install-recommends \
       libjson-c-dev \
       && rm -rf /var/lib/apt/lists/*

# Fuzzing
FROM base AS fuzzing
ENV GEN_FUZZ 1
RUN ./bootstrap \
  && ./configure \
     CC=clang \
     CXX=clang++ \
     --enable-debug \
     --with-fuzzing=libfuzzer \
     --enable-tcti-fuzzing \
     --enable-tcti-device=no \
     --enable-tcti-mssim=no \
     --with-maxloglevel=none \
     --disable-shared \
  && make -j $(nproc) check
RUN cat test-suite.log

# TPM2-TSS
FROM base
RUN ./bootstrap \
	&& ./configure --enable-unit \
	&& make -j$(nproc) check \
	&& make install \
	&& ldconfig
RUN cat test-suite.log
