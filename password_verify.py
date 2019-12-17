#!/usr/bin/env python3
import sha3

def verify(key, data):
    validate = key[16:] + bytes.fromhex(data["ciphertext"])
    keccak_hash = sha3.keccak_256()
    keccak_hash.update(validate)
    if data["mac"] == keccak_hash.hexdigest():
        return True
    else:
        return False

if __name__ == '__main__':
    filename = sys.argv[1] if len(sys.argv) > 1 else None
    print(verify(filename))
