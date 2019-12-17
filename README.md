# Decrypt Ethereum Keyfile
Decrypt an Ethereum keyfile to recover the original private key.

Ethereum keyfiles include a password encrypted private key along with additional metadata relating to the encryption scheme. Keyfiles are stored by default in a `keystore` directory.

Keyfiles are in JSON format.

[Go Ethereum][5] is the official Golang implementation of the Ethereum protocol. It's CLI client, `geth`, does not allow private keys to be exported in plaintext. This is in contrast to Bitcoin Core where the `dumpprivkey` command provides access to decrypted private keys.

The purpose of this project is to decrypt the Ethereum private key from the keyfile when the password is known.

Example Ethereum Keyfile
------------------------
The sample keyfile shown below is generated from a private key 1 encrypted with the password "a":

```json
{
  "address": "7e5f4552091a69125d5dfcb7b8c2659029395bdf",
  "crypto": {
    "cipher": "aes-128-ctr",
    "ciphertext": "7760dc908e875007e47488a7c069636fdac544a647d0e014293a98ec84c333f1",
    "cipherparams": {
      "iv": "75f095a96407bcadb14573fe53fe1b31"
    },
    "kdf": "scrypt",
    "kdfparams": {
      "dklen": 32,
      "n": 262144,
      "p": 1,
      "r": 8,
      "salt": "4aecf9f537e8798e32e59acd3fc9a907f050942f6f19d747474df2cf4f0906ef"
    },
    "mac": "054a378cffa84d6ff14748fceebccd5cea121f91a4464a37e460672dfce9c403"
  },
  "id": "b6b7e620-9c02-416b-a4a6-9f2c5e9469d7",
  "version": 3
}
```
Encryption Scheme
-----------------
The keyfile holds the encrypted private key in the `crypto.ciphertext` field.

The encryption scheme is an AES-128-CTR cipher, using scrypt as a key derivation function (to derive a block cipher key from a text-based password) and message authentication code (MAC) to authenticate the password.

The private key is symmetrically encrypted using AES-128 with block cipher mode CTR. In this case, the [scrypt][6] key derivation function is used to generate an AES symmetric key from the original password. An initialization vector is also required for decryption - and this is held in the `crypto.cipherparams.iv` field.

Relevant fields are:

* `crypto.cipher`: Denotes the cryptographic block-cipher algorithm, key size in bits and block cipher mode of operation.
* `crypto.ciphertext`: The encrypted private key.
* `crypto.cipherparams.iv`: The initialization vector required for AES in counter (CTR) mode.
* `crypto.kdf`: Denotes the key derivation function used - in this case, `srypt`.
* `crypto.kdfparams`: These variables are used in the kdf function - see [decrypt_key.py][8], [scrypt wikipedia][6]
* `crypto.mac`: Message authentication code - used to check the authenticity of the key derived from the user-supplied password.

Key Derivation
--------------
Requires the user-supplied password and the `crypto.kdfparams`.

From [derive_key.py][8]
```py
import hashlib

def key(password, data):
    key = hashlib.scrypt(
        bytes(password, 'utf-8'),
        salt=bytes.fromhex(data["kdfparams"]["salt"]),
        n=data["kdfparams"]["n"],
        r=data["kdfparams"]["r"],
        p=data["kdfparams"]["p"],
        maxmem=2000000000,
        dklen=data["kdfparams"]["dklen"]
        )
    return key  
```

Message Authentication
----------------------
Once the decryption key is derived from the password, it is authenticated by:

* Removing the first 16 bytes from the derived key.
* Concatenating this value (key excluding first 16 bytes) with the ciphertext bytes.
* Comparing the keccak hash of this value with the value of the `crypto.mac` field.
* If these values are the same, the key is authentic.

From [password_verify.py][7]:

```py
import sha3

def verify(key, data):
    validate = key[16:] + bytes.fromhex(data["ciphertext"])
    keccak_hash = sha3.keccak_256()
    keccak_hash.update(validate)
    if data["mac"] == keccak_hash.hexdigest():
        return True
    else:
        return False
```



Generate a Private Key and Keyfile for Testing
----------------------------------------------
The sample keyfile is generated from a private key 1 encrypted with the password "a":

```bash
# cd into a temporary working directory
cd $(mkdir -d)

# Make a key
head -c 32 /dev/random | xxd -ps -c 32 > plain_key.txt

geth --datadir . account import plain_key.txt
```
To run, pass in the path of the keyfile as the first argument to `main.py`. For example:

```bash
./main.py UTC--2019-07-10T14-02-05.192559973Z--7e5f4552091a69125d5dfcb7b8c2659029395bdf
```

You could repeat the process with a randomly generated 32 byte value represented as a hexadecimal string for test purposes:

* Generate a private key
* Repeat the steps above to create an encrypted keyfile
* Run `main.py` with the keyfile as input
* Enter password when prompted
* Output should be your original secret 

Dependencies
------------
Project developed on Ubuntu 18.04. On Ubuntu 16.04, `scrypt` module doesn't have the required OpenSSL version to carry out the necessary hashing. You could upgrade OpenSSL, or spin up a Ubuntu 18.04 VM.

The `sha3` module from [pysha3][1] is used for keccak hashing.

References
----------
* [Pysha3][1] - SHA-3 wrapper(keccak) for Python
* [Keccak code package][2]
* [Useful Stack Exchange answer][3]
* [Bitcoin Core dumpprivkey command][4]
* [Go Ethereum][5], GitHub repo
* [scrypt key derivation function][6]


[1]: https://pypi.org/project/pysha3/
[2]: https://github.com/XKCP/XKCP
[3]: https://ethereum.stackexchange.com/questions/3720/how-do-i-get-the-raw-private-key-from-my-mist-keystore-file
[4]: https://bitcoin.org/en/developer-reference#dumpprivkey
[5]: https://github.com/ethereum/go-ethereum
[6]: https://en.wikipedia.org/wiki/Scrypt
[7]: /password_verify.py
[8]: /derive_key.py
