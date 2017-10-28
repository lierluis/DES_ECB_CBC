# DES_ECB_CBC

Encryption algorithm DES and block cipher modes ECB and CBC written in Java

* [Data Encryption Standard](https://en.wikipedia.org/wiki/Data_Encryption_Standard)
* [DES in detail](https://www.memresearch.org/grabbe/des.htm)
* [Electronic Codebook](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#ECB)
* [Cipher Block Chaining](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#CBC)

To compile and run:
```
javac Crypto.java && java Crypto
```     

Sample output:
```
-----DES--------------------------
 Plaintext: 00000001 00100011 01000101 01100111 10001001 10101011 11001101 11101111
       Key: 00010011 00110100 01010111 01111001 10011011 10111100 11011111 11110001
Ciphertext: 10000101 11101000 00010011 01010100 00001111 00001010 10110100 00000101
-----ECB 1------------------------
 Plaintext: I LOVE SECURITY
       Key: ABCDEFGH
Ciphertext: 198 252 213 112 106 165 23 145 29 52 125 61 85 217 102 155
-----ECB 2------------------------
 Plaintext: GO GATORS!
       Key: ABCDEFGH
Ciphertext: 86 100 180 248 126 142 38 5 255 224 149 93 149 189 237 2
-----CBC 1------------------------
 Plaintext: I LOVE SECURITY
       Key: ABCDEFGH
        IV: ABCDEFGH
Ciphertext: 63 69 76 252 154 205 193 162 46 88 102 161 151 14 56 97
-----CBC 2------------------------
 Plaintext: SECURITYSECURITY
       Key: ABCDEFGH
        IV: ABCDEFGH
Ciphertext: 232 111 39 242 85 25 41 106 39 52 175 62 196 141 176 70
```
