# YubiSigner

The tool provides a convenient way to sign and securely verify file signatures with Yubico YubiKey, utilizing an organization's PKI infrastructure.

```
yubisigner sign -i data.txt -o data.sig -p PINCODE

yubisigner verify -i data.txt -s data.sig -C CA.crt
Verified OK
```

The signature file contains PEM encoded signature and signer's certificate.


## About

YubiKey piv applet supports file signing using certificate pair stored in 0x9c slot.

You can generate file signature using [yubico-piv-tool](https://developers.yubico.com/yubico-piv-tool/)
```
yubico-piv-tool -a verify-pin --sign -s 9c -H SHA512 -A RSA2048 -i data.txt -o data.sig
```
it generates a binary signature file that can be verified by OpenSSL:
```
openssl dgst -sha512 -verify pubkey.pem -signature data.sig data.txt
```

## Problem:

If we want to verify received data file, we need:

1. data file
2. signature file
3. signer's public key

signature file contains binary data:
```
hexdump data.sig 
0000000 72b4 78e6 8fc5 0655 352c 5dad 9078 b756
0000010 9c13 c27a 5735 5854 4935 407a 2cfb e18d
0000020 7015 64b7 9464 dd07 f358 63b4 651e 20f1
0000030 6b24 dc14 ce35 24d6 e221 9c34 e1ce c050
0000040 2ddc 2ac1 0256 441a 2901 d856 d257 31a7
0000050 8bd7 8442 1d16 730c 07be aa1c 0894 9d73
0000060 8b9d 1200 0b43 e724 39f4 bb62 e8d4 9fc0
0000070 e182 1ef6 6497 cc51 30b9 c7ca 7542 6855
0000080 426b 5e62 8481 4d10 15c0 6a1d 4f8f 419c
0000090 d5ac dafa 3edb 1ae2 bf18 594b e2fa 3e80
00000a0 95c8 9bcf 7d1a bb3f d6e8 06b7 9f53 82dd
00000b0 ebcd 6a9d 794c 942e ac6d 4dc2 9c0f 3822
00000c0 a77a 6ebc ed64 5bfd dbdd cd61 a781 c023
00000d0 21eb b7e0 48e6 9949 a0ca fbdd e0d5 28b7
00000e0 d5df 0a5d f474 fb9d 371d 9aa0 7206 33b9
00000f0 174e 2c55 e8a8 45de de6a e320 0d10 194d
0000100
```
It would be more convenient if the signature was in text format. Also, the signature doesn't contain information about the signer, and we need his public key to verify it. Signer can send it with the signature and the data. But if the data is altered, how can we be sure that the public key is not?

To solve this problem, we can use PKI infrastructure. If the signer's certificate is signed with trusted certificate authority, we can verify it's legitimacy and the data integrity.

**YubiSigner** concatenates the signature and the signer's certificate in PEM format into a signature file. As far as it is plaintext, it can be transferred easily.

## PKI
### Preparation

Generate and self sign the CA authority certificate:
```
openssl genrsa -out ca.key 2048
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.crt
```

### Prepare YubiKey
We need a separate private key and certificate signed by CA on each YubiKey.

First, we need to generate the private key and certificate signing request:
```
yubico-piv-tool -s 9c -a generate -A RSA2048 -o user1.pub
yubico-piv-tool -s 9c -a verify-pin -a request-certificate -S '/CN=user1/' -i user1.pub -o user1.csr
```

Then, sign it with our CA:
```
openssl x509 -req -in user1.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out user1.crt
```

Now we need to import this new certificate into YubiKey:
```
yubico-piv-tool -s 9c -a import-certificate -i user1.crt
```

That's all. 

## Installation
Under the hood YubiSigner uses [piv-go](https://github.com/go-piv/piv-go) library.

On MacOS, piv-go doesn't require any additional packages.

To build on Linux, piv-go requires PCSC lite. To install on Debian-based distros, run:

```
sudo apt-get install libpcsclite-dev
```

On Fedora:

```
sudo yum install pcsc-lite-devel
```

On CentOS:

```
sudo yum install 'dnf-command(config-manager)'
sudo yum config-manager --set-enabled PowerTools
sudo yum install pcsc-lite-devel
```

On FreeBSD:

```
sudo pkg install pcsc-lite
```

On Windows:

No prerequisites are needed. The default driver by Microsoft supports all functionalities which get tested by unittests. However if you run into problems try the official YubiKey Smart Card Minidriver. Yubico states on their website the driver adds additional smart functionality.

Please notice the following:

Windows support is best effort due to lack of test hardware. This means the maintainers will take patches for Windows, but if you encounter a bug or the build is broken, you may be asked to fix it.
