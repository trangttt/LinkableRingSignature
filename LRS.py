import random
import sys

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from pycoin.ecdsa.Point import Point, NoSuchPointError

from LinkableRingSignature.constants import (
    HASH_FUNCTION as HASHF,
    ECC_CURVE,
    ECC_GENERATOR as g
)
from LinkableRingSignature import utils


randomNumber = lambda: random.randint(0, ECC_CURVE.order())

def toPointH2(publicKeys):
    """
    Hash list of public Keys into a point
    :param publicKeys: list of publicKeys
    :return: a point
    """
    # concat to bytes
    bKeyConcat = _pointsToBytes(publicKeys)
    # hash
    bKeysHash = HASHF(bKeyConcat).digest()
    # convert to int
    iKeysHash = utils.bytes2Int(bKeysHash)
    # convert to point
    point = _findPoint(iKeysHash)
    return point

def _findPoint(x):
    """
    Find value y of an ECC point given value of x
    :param x:
    :return: ECC point
    """
    x -= 1
    while True:
       x += 1
       try:
           # ySq = x* + ax + b (mode p)
           # y = moduleo_square(ySq)
           y = g.y_values_for_x(x)
       except ValueError:
            continue
       y = y[0]
       try:
           point = Point(x, y, ECC_CURVE)
           return point
       except NoSuchPointError as e:
           continue


def toNumberH1(publicKeys, P1, message, P2, P3):
    """
    Hash the following objects into an integer
    :param publicKeys: list of Publickeys
    :param P1: y Tilde
    :param message: message to be signed in bytes
    :param P2: Point
    :param P3: Point
    :return: integer
    """
    bKeys = _pointsToBytes(publicKeys)
    bP1 = _pointsToBytes([P1])
    bP23 = _pointsToBytes([P2, P3])
    plainText = bKeys + bP1 + message + bP23
    hashed =  HASHF(plainText).digest()
    return utils.bytes2Int(hashed)

def _pointsToBytes(points):
    """
    Concat all points into bytes array
    :param points: poinst to be concat
    :return: bytes
    """
    bPoints = b''
    for point in points:
        bPoints += utils.pointTobytes(point)
    return bPoints


def sign(message, publicKeys, privateKey, index):
    noKeys = len(publicKeys)

    # step 1
    h = toPointH2(publicKeys)
    yTilde = privateKey * h

    # step 2
    u = randomNumber()

    c = [0] * noKeys
    nextIndex = (index + 1) % noKeys
    c[nextIndex] = toNumberH1(publicKeys, yTilde, message, u * g, u * h)

    # step 3
    s = [0] * noKeys
    for i in list( (nextIndex + i)%noKeys for i in range(noKeys-1)):
        nextI = (i+1) % noKeys
        si = randomNumber()
        s[i] = si

        point1 = si * g + c[i] * publicKeys[i]
        point2 = si * h + c[i] * yTilde
        c[nextI] = toNumberH1(publicKeys, yTilde, message, point1, point2)


    # step 4
    s[index] = (u - (privateKey * c[index])) % ECC_CURVE.order()

    return (c[0], s, yTilde)


def verify(message, publicKeys, signature):
    noKeys = len(publicKeys)
    cZero, s, yTilde = signature
    assert len(s) == noKeys, "Invalid number of s %s != %s Number of Keys" % (len(s), noKeys)

    # step 1
    h = toPointH2(publicKeys)
    # zPrime = [0] * noKeys
    # zDPrime = [0] * noKeys
    c = [0]  * noKeys
    c[0] = cZero

    for i in range(noKeys):
        zPrime = s[i] * g + c[i] * publicKeys[i]
        zDPrime = s[i] * h + c[i] * yTilde
        c[(i+1)%noKeys] = toNumberH1(publicKeys, yTilde, message, zPrime, zDPrime)

    return c[0] == cZero

def areLinked(sig1, sig2):
    """
    Check whether two signatures are signed by the same keys
    NOTE: these two signatures should be generated from the same group. aka. list of public keys.
    :param sig1: signature 1
    :param sig2: signature 2
    :return:  boolean value
    """
    _,_, yTilde1 = sig1
    _,_, yTilde2 = sig2
    return yTilde1 == yTilde2

def generateKeys(number=10):
    for _ in range(number):
        priv = ec.generate_private_key(ec.SECP256K1(), default_backend())
        privValue = priv.private_numbers().private_value
        pub = priv.public_key().public_numbers()
        pubValue = Point(pub.x, pub.y, ECC_CURVE)
        yield (privValue, pubValue)




if __name__ == "__main__":
    import sys
    message = b'Trang'
    keys = list(generateKeys())
    publicKeys = [k[1] for k in keys]
    privateKeys = [k[0] for k in keys]
    index = int(sys.argv[1])
    signature1 = sign(message, publicKeys, privateKeys[index], index)
    print(verify(message, publicKeys, signature1))
    print(signature1)


    message = b'AnotherTrang'
    signature2 = sign(message, publicKeys, privateKeys[index], index)
    print(verify(message, publicKeys, signature2))
    print(signature2)


    print(areLinked(signature1, signature2))




