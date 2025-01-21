#!/bin/bash
# This script generates a CSR 

THREAD=$1
algorithm=$2
subject=$3

key_cmd=""
key_algorithm=$(echo ${algorithm} | cut -d ':' -f1)

if [[ "${key_algorithm}" == "RSA" ]]; then
    key_opt=$(echo ${algorithm} | cut -d ':' -f2)
    # Generate key
    key_cmd="openssl genpkey -algorithm ${key_algorithm} -pkeyopt rsa_keygen_bits:${key_opt} 2>/dev/null"
elif [[ "${key_algorithm}" == "EC" ]]; then
    key_opt=$(echo ${algorithm} | cut -d ':' -f2)
    # Generate key
    key_cmd="openssl genpkey -algorithm ${key_algorithm} -pkeyopt ec_paramgen_curve:${key_opt} 2>/dev/null"
elif [[ "${key_algorithm}" == "ED25519" ]]; then
    # Generate key
    key_cmd="openssl genpkey -algorithm ${key_algorithm} 2>/dev/null"
fi

# Change "#" with ${THREAD}
changed_subject=$(echo "$subject" | sed "s/#/\${THREAD}/g")

# Create CSR
#csr_cmd="openssl req -new -key <(${key_cmd}) -subj /CN=enduser${THREAD}/O=enduser${THREAD}_org/C=PT"
csr_cmd="openssl req -new -key <($key_cmd) -subj ${changed_subject}"
echo -n "-----BEGIN CERTIFICATE REQUEST-----\n"
eval ${csr_cmd} | grep -v "CERTIFICATE REQUEST" | tr -d '\n'
echo -n "\n-----END CERTIFICATE REQUEST-----"

