#!/usr/bin/env python3
import sys
import hashlib
#import scrypt
import sha3 # For keccak: https://pypi.org/project/pysha3/
import json

def read_json(filename):
    with open(filename) as f_in:
        return(json.load(f_in))

def main(filename):
    if filename == None:
        filename = "key.json"
    fulldata = read_json(filename)
    data = fulldata["crypto"]

    key = hashlib.scrypt(
        bytes('a', 'utf-8'),
        salt=bytes.fromhex(data["kdfparams"]["salt"]),
        n=data["kdfparams"]["n"],
        r=data["kdfparams"]["r"],
        p=data["kdfparams"]["p"],
        maxmem=2000000000,
        dklen=data["kdfparams"]["dklen"]
        )
    validate = key[16:] + bytes.fromhex(data["ciphertext"])
    keccak_hash = sha3.keccak_256()
    keccak_hash.update(validate)
    print(keccak_hash.hexdigest())
    

if __name__ == '__main__':
    filename = sys.argv[1] if len(sys.argv) > 1 else None
    main(filename)
