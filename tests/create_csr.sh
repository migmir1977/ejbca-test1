#!/bin/bash
# This script generates a CSR 

THREAD=$1

# Generate key
key_cmd="openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 2>/dev/null"

# Create CSR
csr_cmd="openssl req -new -key <($key_cmd) -subj /CN=enduser${THREAD}/O=enduser${THREAD}_org/C=PT"
echo -n "-----BEGIN CERTIFICATE REQUEST-----\n"
eval $csr_cmd | grep -v "CERTIFICATE REQUEST" | tr -d '\n'
echo -n "\n-----END CERTIFICATE REQUEST-----"

