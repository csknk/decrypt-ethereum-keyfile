Decrypt Ethereum Keyfile
========================

The sample keyfile is generated from a private key 1 encrypted witht he password "a":

```bash
echo "0000000000000000000000000000000000000000000000000000000000000001" > plain_key.txt
geth --datadir . account import plain_key.txt
```

Dependencies
------------
Project developed on Ubuntu 18.04. On Ubuntu 16.04, `scrypt` module doesn't have the required OpenSSL version to carry out the necessary hashing. You could upgrade OpenSSL, or spin up a Ubuntu 18.04 VM.

The `sha3` module from [pysha3][1] is used for keccak hashing.

References
----------
* [Pysha3][1] - SHA-3 wrapper(keccak) for Python
* [Keccak code package][2]
* [Useful Stack Exchange answer][3]


[1]: https://pypi.org/project/pysha3/
[2]: https://github.com/XKCP/XKCP
[3]: https://ethereum.stackexchange.com/questions/3720/how-do-i-get-the-raw-private-key-from-my-mist-keystore-file
