#!/bin/bash

# private_key_into_bitcoin_wif.sh: convert secp256k1 private key in hexadicimal number (HEX) to Bitcoin Wallet Import Format (WIF)
# Examples: 
# $ bash private_key_into_bitcoin_wif.sh "000ffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364139" > private_key_bitcoin.wif
# $ bash private_key_into_bitcoin_wif.sh $(< input_file.txt) > private_key_bitcoin.wif
# $ cat priv_key.hex | xargs bash private_key_into_bitcoin_wif.sh > private_key_bitcoin.wif
# $ bash private_key_into_bitcoin_wif.sh fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364139 | echo "$(cat) importedkeylabel false" | xargs bitcoin-cli importprivkey && bitcoin-cli getaddressesbylabel importedkeylabel
# $ bash private_key_into_bitcoin_wif.sh $( printf "%02x" $( od -A n -N 32 -t u1 /dev/random )
# $ bash private_key_into_bitcoin_wif.sh $(for i in {1..8}; do printf "%08x" $SRANDOM; done)
# $ bash private_key_into_bitcoin_wif.sh $(openssl ecparam -genkey -name secp256k1 -outform DER | openssl asn1parse -inform DER | sed -n '3p' | tail -c 64)
# $ openssl rand -hex 32 | xargs bash private_key_into_bitcoin_wif.sh
# $ xxd -l 32 -p -c 32 /dev/random | xargs bash private_key_into_bitcoin_wif.sh
# $ hexdump -n 32 -v -e "/1 \"%02x\"" /dev/random | xargs bash private_key_into_bitcoin_wif.sh
# $ od -A n -t x1 -v -N 32 -w32 /dev/random | tr -d " " | xargs bash private_key_into_bitcoin_wif.sh
# $ od -t x --width=32 --endian=big -A n -v --skip-bytes=7 --read-bytes=32 priv_key_secp256k1.openssl.der | tr -d [:blank:] | xargs bash private_key_into_bitcoin_wif.sh
# $ privkey=$( openssl asn1parse -in priv_key_secp256k1.der -inform DER | sed -n '3p' ); bash private_key_into.bitcoin.wif.sh ${privkey: -64} 
# $ openssl asn1parse -in priv_key_secp256k1.der -inform der -offset=5 -length=34 | cut -d ':' -f 4 | xargs bash private_key_into_bitcoin_wif.sh
# (Extracting a private key using certutil.exe parser in cmd.exe only)  C:\> for /f "usebackq tokens=3-19" %a in (`certutil.exe -asn priv_key_secp256k1.openssl.der ^| findstr "\<|....................................................;\>"`) do @echo | set /p=%a%b%c%d%e%f%g%h%i%j%k%l%m%n%o%p
# $ openssl ec -in private_key.openssl.pem -text | grep -A 3 'priv:' | tail -n 3 | tr -d -c [:xdigit:] | xargs bash private_key_into_bitcoin_wif.sh
# $ gpg --list-packets --verbose gpg.key | grep skey | grep -o -w -m 1 '[[:xdigit:]]\{64\}' | xargs bash private_key_into_bitcoin_wif.sh
# $ zsh private_key_into_bitcoin_wif.sh "000ffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364139"

declare -r BASE58_CHARSET="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
declare hex_priv_key="$1"
declare u_limit=fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140
declare -i counter=0

#######################################
# Input validation - 64 characters and within the elliptic curve secp256k1 private key limit
#######################################
if [ ${#hex_priv_key} -ne 64 ]; then
  echo "ERROR: The input argument is not 64 characters long. If the number is shorter then it needs to be prepanded with zeros so it looks like in the example: 000ffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364139"
  exit 1
fi

for (( counter=0; counter<64; counter+=2 )); do
  if [[ $(( 16#${hex_priv_key:$counter:2} )) -lt $(( 16#${u_limit:$counter:2} )) ]]; then
    break
  elif [[ $(( 16#${hex_priv_key:$counter:2} )) -eq $(( 16#${u_limit:$counter:2} )) ]]; then
    continue
  else
    echo "ERROR: The input priv key is not within valid secp256k1 range of ${u_limit}"
    exit 2
  fi
done

#######################################
# Conversion from HEX to WIF
#######################################
declare -r PRIVATE_KEY_WIF_PREFIX="80"
declare -r COMPRESSION_FLAG_WIF_SUFFIX="01" # replace the characters "01" with "" in order to output a so-called uncompressed variant 
declare hex_annotated_priv_key="${PRIVATE_KEY_WIF_PREFIX}${hex_priv_key}${COMPRESSION_FLAG_WIF_SUFFIX}"
if command -v sha256sum >/dev/null
  then
  declare sha256_digest=$( for (( counter=0; counter<${#hex_annotated_priv_key}; counter+=2 )) ; do printf "\x${hex_annotated_priv_key:$counter:2}" ; done | sha256sum -b )
  declare double_sha256_digest=$( for (( counter=0; counter<64; counter+=2 )) ; do printf "\x${sha256_digest:$counter:2}" ; done | sha256sum -b )
elif command -v shasum >/dev/null
  then
  declare sha256_digest=$( for (( counter=0; counter<${#hex_annotated_priv_key}; counter+=2 )) ; do printf "\x${hex_annotated_priv_key:$counter:2}" ; done | shasum -a 256 -b )
  declare double_sha256_digest=$( for (( counter=0; counter<64; counter+=2 )) ; do printf "\x${sha256_digest:$counter:2}" ; done | shasum -a 256 -b )
elif command -v openssl >/dev/null
  then
  declare double_sha256_digest=$( for (( counter=0; counter<${#hex_annotated_priv_key}; counter+=2 )) ; do printf "\x${hex_annotated_priv_key:$counter:2}" ; done | openssl dgst -digest -sha256 -binary | openssl dgst -digest -sha256 -r )
else
  echo "There isn't sha256sum or shasum or openssl installed. Script execution interrupted."
  exit 1
fi
hex_annotated_priv_key="${hex_annotated_priv_key}${double_sha256_digest:0:8}"
declare dividend="${hex_annotated_priv_key}"
declare -i -r divisor=${#BASE58_CHARSET}
declare -i -r divisor_length=${#divisor}
declare -i subdividend=0
declare quotient="1"
declare -i i=0
declare -i j=0
declare -i position=0
declare -i leading_zeros=0
declare -i initial_zeros_in_priv_key=0
declare b58_int_string=""

while ((${#dividend} >= ${divisor_length})); do
  quotient=""
  for (( position=0; position<${#dividend}; position++ )); do
    subdividend=$((subdividend*16+16#${dividend:$position:1}))
    printf -v quotient "%s%X" "${quotient}" $((subdividend/divisor))
    subdividend=$((subdividend%divisor))
  done
  printf -v b58_int_string "%s%02d" "${b58_int_string}" "${subdividend}"
  subdividend=0
  for (( leading_zeros=0; leading_zeros<${#quotient}; leading_zeros++ )); do
    if [ ${quotient:$leading_zeros:1} != "0" ]; then
      break
    fi
  done
  dividend=${quotient:$leading_zeros}
done

if (( leading_zeros != ${#quotient} )); then
  printf -v b58_int_string "%s%02d" "${b58_int_string}" $(( 16#${dividend} ))
fi

for (( initial_zeros_in_priv_key=0; initial_zeros_in_priv_key<${#hex_annotated_priv_key}; initial_zeros_in_priv_key+=2 )); do
  if [[ ${hex_annotated_priv_key:$initial_zeros_in_priv_key:2} == "00" ]]; then
	printf -v b58_int_string "%s%c" "${b58_int_string}" "0"
  else
    break
  fi
done

declare -i dec=0
for (( j=${#b58_int_string}-2; j >= 0; j-=2 )); do
  dec=$(( 10#${b58_int_string:$j:2} ))
  printf "%c" ${BASE58_CHARSET:$dec:1}
done

printf "\n"

# Release date: 2022-08-23
