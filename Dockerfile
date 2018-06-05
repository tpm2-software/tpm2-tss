FROM ubuntu:18.04
RUN apt-get update
RUN apt-get install -y \
    autoconf \
    autoconf-archive \
    automake \
    build-essential \
    g++ \
    gcc \
    git \
    libssl-dev \
    libtool \
    m4 \
    net-tools \
    pkg-config \
    wget

# OpenSSL
ARG openssl_name=openssl-1.1.0h
WORKDIR /tmp
ADD https://www.openssl.org/source/$openssl_name.tar.gz .
RUN tar xvf $openssl_name.tar.gz
WORKDIR $openssl_name
RUN ./config --prefix=/usr/local/openssl --openssldir=/usr/local/openssl
RUN make -j$(nproc)
RUN make install
RUN openssl version

# IBM's Software TPM 2.0
ARG ibmtpm_name=ibmtpm1119
WORKDIR /tmp
RUN wget "https://downloads.sourceforge.net/project/ibmswtpm2/$ibmtpm_name.tar.gz"
RUN sha256sum $ibmtpm_name.tar.gz | grep ^b9eef79904e276aeaed2a6b9e4021442ef4d7dfae4adde2473bef1a6a4cd10fb
RUN mkdir -p $ibmtpm_name
RUN tar xvf $ibmtpm_name.tar.gz -C $ibmtpm_name
WORKDIR $ibmtpm_name/src
RUN CFLAGS="-I/usr/local/openssl/include" make -j$(nproc)
RUN cp tpm_server /usr/local/bin

RUN apt-get install -y \
    libcmocka0 \
    libcmocka-dev \
    libgcrypt20-dev \
    libtool \
    liburiparser-dev \
    uthash-dev

# TPM2-TSS
COPY . /tmp/tpm2-tss/
WORKDIR /tmp/tpm2-tss
RUN ./bootstrap
RUN ./configure --enable-unit
RUN make -j$(nproc) check
RUN make install
RUN ldconfig
ENV LD_LIBRARY_PATH /usr/local/lib
RUN cat test-suite.log

