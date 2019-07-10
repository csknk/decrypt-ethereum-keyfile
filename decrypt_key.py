#!/usr/bin/env python3
import sys
import hashlib
import sha3

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
