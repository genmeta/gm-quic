# gen root key
openssl ecparam -name secp384r1 -genkey -noout -out rootCA-ECC.key
# gen self-signed cert
openssl req -new -x509 -days 3650 -key rootCA-ECC.key -sha384 -out rootCA-ECC.crt

# gen server private key
openssl ecparam -name secp384r1 -genkey -noout -out quic-test-net-ECC.key
# create csr 
openssl req -new -key quic-test-net-ECC.key -out quic-test-net.csr
# gen server cert with v3
cat <<EOT > openssl.cnf
[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = quic.test.net
EOT

openssl x509 -req \
  -extfile openssl.cnf -extensions v3_req \
  -in quic-test-net.csr \
  -CA rootCA-ECC.crt -CAkey rootCA-ECC.key -CAcreateserial \
  -out quic-test-net-ECC.crt -days 365 -sha384

# view info in quic-test-net-ECC.crt
openssl x509 -in quic-test-net-ECC.crt -text -noout
