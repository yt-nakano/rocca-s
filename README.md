# Encryption algorithm Rocca-S

This software is a reference implementation of encryption algorithm Rocca-S

# Overview

Rocca-S is an authentiated encryption with associated data (AEAD) algorithm with 256-bit key and 256-bit tag.
Rocca-S achieves an encryption/decryption speed of more than 200 Gbps in both 
raw encryption scheme and AEAD scheme use cases on an Intel(R) Core(TM) i9-12900K and can provide 256-bit and 
128-bit security against classical and quantum adversaries respectively.

# Documentation

Detail of the specification can be found in the following:

https://datatracker.ietf.org/doc/draft-nakano-rocca-s/

The paper is also presented at the 28th European Symposium on
Research in Computer Security (ESORICS 2023):

```
R. Anand, S. Banik, A. Caforio, K. Fukushima, T. Isobe, S. Kiyomoto, F. Liu, Y. Nakano, K. Sakamoto, and N. Takeuchi.
An Ultra-High Throughput AES-based Authenticated Encryption Scheme for 6G: Design and Implementation.
28th European Symposium on Research in Computer Security. 2023.
```


# License

Please refer LICENSE file.

# Build

For Ubuntu/Debian, this software can be built by the following commands:

```bash
$ sudo apt install build-essential cmake libgtest-dev libabsl-dev
$ mkdir build
$ cd build
$ cmake ..
$ make
```

The test software can be executed by the following command: 

```bash
$ ./test/test_rocca-s_ref
```
