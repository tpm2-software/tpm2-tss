FROM ubuntu:trusty

RUN apt -y update && \
  apt -y install \
    autoconf-archive \
    libcmocka0 \
    libcmocka-dev \
    build-essential \
    wget \
    git \
    libssl-dev \
    pkg-config \
    gcc \
    g++ \
    m4 \
    libtool \
    automake \
    autoconf

RUN wget https://downloads.sourceforge.net/project/ibmswtpm2/ibmtpm532.tar && \
  sha256sum ibmtpm532.tar | grep -q ^abc0b420257917ccb42a9750588565d5e84a2b4e99a6f9f46c3dad1f9912864f && \
  mkdir ibmtpm532 && \
  tar axf ibmtpm532.tar -C ibmtpm532 && \
  make -C ibmtpm532/src -j$(nproc)

RUN git clone https://github.com/01org/TPM2.0-TSS && \
  cd TPM2.0-TSS && \
  ./bootstrap && \
  mkdir ./build && \
  cd ./build && \
  ../configure --enable-unit --with-simulatorbin=$(pwd)/../../ibmtpm532/src/tpm_server && \
  make -j$(nproc) && \
  make simulator-build && \
  make -j$(nproc) check && \
  make simulator-start && \
  test/tpmclient/tpmclient && \
  make simulator-stop
