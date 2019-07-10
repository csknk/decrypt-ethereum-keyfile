#!/usr/bin/env python3

import sys, json
from getpass import getpass
from password_verify import verify
from decrypt_key import key

from Crypto.Cipher import AES
from Crypto.Util import Counter

def read_json(filename):
    with open(filename) as f_in:
        return(json.load(f_in))

def main(filename):
    if filename == None:
        filename = "key.json"
    fulldata = read_json(filename)
    data = fulldata["crypto"]
    password = getpass()
    k = key(password, data)
    print("key: {}".format(key))
    if (verify(k, data)):
        print("Password verified.")
        
        #print("iv_int: {}".format(data["cipherparams"]["iv"]))
        iv_int = int(data["cipherparams"]["iv"], 16)
        ctr = Counter.new(AES.block_size * 8, initial_value=iv_int)
        # Note first 16 bytes of the derived key
        dec_suite = AES.new(k[:16], AES.MODE_CTR, counter=ctr)
        decrypted_private_key = dec_suite.decrypt(bytes.fromhex(data["ciphertext"]))
        print(decrypted_private_key)

    else:
        print("Password NOT verified.")

if __name__ == '__main__':
    filename = sys.argv[1] if len(sys.argv) > 1 else None
    main(filename)

