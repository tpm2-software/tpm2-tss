#!/bin/bash

# set -x

set -euf

echo "Creating ekcert for $1 => $3"
echo "Creating ekcert for $2 => $4"

EKCADIR="$(dirname $(realpath ${0}))/"

CA_DIR="$(mktemp -d ekca-XXXXXX)"

pushd "$CA_DIR"

mkdir root-ca
pushd root-ca

mkdir certreqs certs crl newcerts private
touch root-ca.index
echo 00 > root-ca.crlnum
echo 1000 > root-ca.serial
echo "123456" > pass.txt

cp "${EKCADIR}/root-ca.cnf" ./
export OPENSSL_CONF=./root-ca.cnf

openssl req -new -out root-ca.req.pem -passout file:pass.txt

#openssl req -verify -in root-ca.req.pem \
#    -noout -text \
#    -reqopt no_version,no_pubkey,no_sigdump \
#    -nameopt multiline -passin file:pass.txt

openssl ca -selfsign \
    -in root-ca.req.pem \
    -out root-ca.cert.pem \
    -extensions root-ca_ext \
    -startdate `date +%y%m%d000000Z -u -d -1day` \
    -enddate `date +%y%m%d000000Z -u -d +10years+1day` \
    -passin file:pass.txt -batch

#openssl x509 -in ./root-ca.cert.pem \
#    -noout -text \
#    -certopt no_version,no_pubkey,no_sigdump \
#    -nameopt multiline

openssl verify -verbose -CAfile root-ca.cert.pem \
    root-ca.cert.pem

popd #root-ca

mkdir intermed-ca
pushd intermed-ca

mkdir certreqs certs crl newcerts private
touch intermed-ca.index
echo 00 > intermed-ca.crlnum
echo 2000 > intermed-ca.serial
echo "abcdef" > pass.txt

cp "${EKCADIR}/intermed-ca.cnf" ./
export OPENSSL_CONF=./intermed-ca.cnf

openssl req -new -out intermed-ca.req.pem -passout file:pass.txt

openssl req -new \
    -key private/intermed-ca.key.pem \
    -out intermed-ca.req.pem \
    -passin file:pass.txt

#openssl req  -verify -in intermed-ca.req.pem \
#    -noout -text \
#    -reqopt no_version,no_pubkey,no_sigdump \
#    -nameopt multiline

cp intermed-ca.req.pem  \
    ../root-ca/certreqs/

pushd ../root-ca
export OPENSSL_CONF=./root-ca.cnf

openssl ca \
    -in certreqs/intermed-ca.req.pem \
    -out certs/intermed-ca.cert.pem \
    -extensions intermed-ca_ext \
    -startdate `date +%y%m%d000000Z -u -d -1day` \
    -enddate `date +%y%m%d000000Z -u -d +5years+1day` \
    -passin file:pass.txt -batch

#openssl x509 -in certs/intermed-ca.cert.pem \
#    -noout -text \
#    -certopt no_version,no_pubkey,no_sigdump \
#    -nameopt multiline

openssl verify -verbose -CAfile root-ca.cert.pem \
    certs/intermed-ca.cert.pem

cp certs/intermed-ca.cert.pem \
    ../intermed-ca

popd #root-ca

popd #intermed-ca

mkdir ek
pushd ek

cp "${EKCADIR}/ek.cnf" ./
export OPENSSL_CONF=ek.cnf
echo "abc123" > pass.txt

cp "$1" ../intermed-ca/certreqs/ek.pub.pem

openssl req -new -nodes -newkey rsa:2048 -passin file:pass.txt -out ../intermed-ca/certreqs/nonsense.csr.pem

#openssl req  -verify -in ../intermed-ca/certreqs/nonsense.csr.pem \
#    -noout -text \
#    -reqopt no_version,no_pubkey,no_sigdump \
#    -nameopt multiline

pushd ../intermed-ca
export OPENSSL_CONF=./intermed-ca.cnf

openssl x509 -req -in certreqs/nonsense.csr.pem -force_pubkey certreqs/ek.pub.pem -out certs/ek.cert.der \
    -outform DER -extfile ../ek/ek.cnf -extensions ek_ext -set_serial 12345 \
    -CA intermed-ca.cert.pem -CAkey private/intermed-ca.key.pem -passin file:pass.txt

#openssl x509 -req -in csrs/oemProvCertTPM.csr -extfile configs/oemProvCertTPM.cnf -extensions ext -CA certs/oemSubCA2Cert.pem -CAkey privateKeys/oemSubCA2.key -passin file:passphrase.txt -set_serial 12345 -days $validity_oem_prov_cert -force_pubkey pc.pub.pem -out certs/oemProvCertTPM.pem

cp certs/ek.cert.der ../ek

popd #intermed-ca

#openssl x509 -in ek.cert.der -inform DER -text -noout
#openssl rsa -in ek.pub.pem -pubin -text -noout
#openssl asn1parse -in ek.cert.der -inform DER

popd #EK

# ECC Certificate

mkdir ekecc
pushd ekecc

cp "${EKCADIR}/ek.cnf" ./
export OPENSSL_CONF=ek.cnf
echo "abc123" > pass.txt

cp "$2" ../intermed-ca/certreqs/ekecc.pub.pem

openssl req -new -nodes -newkey rsa:2048 -passin file:pass.txt -out ../intermed-ca/certreqs/nonsense.csr.pem

#openssl req  -verify -in ../intermed-ca/certreqs/nonsense.csr.pem \
#    -noout -text \
#    -reqopt no_version,no_pubkey,no_sigdump \
#    -nameopt multiline

pushd ../intermed-ca
export OPENSSL_CONF=./intermed-ca.cnf

openssl x509 -req -in certreqs/nonsense.csr.pem -force_pubkey certreqs/ekecc.pub.pem -out certs/ekecc.cert.der \
    -outform DER -extfile ../ek/ek.cnf -extensions ek_ext -set_serial 12345 \
    -CA intermed-ca.cert.pem -CAkey private/intermed-ca.key.pem -passin file:pass.txt

#openssl x509 -req -in csrs/oemProvCertTPM.csr -extfile configs/oemProvCertTPM.cnf -extensions ext -CA certs/oemSubCA2Cert.pem -CAkey privateKeys/oemSubCA2.key -passin file:passphrase.txt -set_serial 12345 -days $validity_oem_prov_cert -force_pubkey pc.pub.pem -out certs/oemProvCertTPM.pem

cp certs/ekecc.cert.der ../ek

popd #intermed-ca

#openssl x509 -in ek.cert.der -inform DER -text -no out
#openssl rsa -in ek.pub.pem -pubin -text -noout
#openssl asn1parse -in ek.cert.der -inform DER

popd #EK

popd #CA_DIR

cp "${CA_DIR}/ek/ek.cert.der" "$3"
cp "${CA_DIR}/ek/ekecc.cert.der" "$4"
cp "${CA_DIR}/intermed-ca/intermed-ca.cert.pem" "$5"
cp "${CA_DIR}/root-ca/root-ca.cert.pem" "$6"

rm -rf $CA_DIR
