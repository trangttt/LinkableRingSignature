import hashlib
from pycoin.ecdsa.secp256k1 import secp256k1_generator as generator


HASH_FUNCTION = hashlib.sha256

ECC_CURVE = generator.curve()
ECC_GENERATOR = generator


# Keysie is relative to prime order bitlength
KEY_SIZE =  ECC_GENERATOR._p.bit_length()
INTEGER_BYTES = KEY_SIZE // 8