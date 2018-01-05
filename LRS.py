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
    try:
        yCandidates = ECC_CURVE.y_values_for_x(iKeysHash)
    except ValueError as e:
        print('Cannot find Point for publicKeys' , e)
        sys.exit(1)

    try:
        return Point(iKeysHash, yCandidates[0], ECC_CURVE)
    except NoSuchPointError as e:
        return Point(iKeysHash, yCandidates[1], ECC_CURVE)


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
    for i in list(range(nextIndex, noKeys)) + list(range(index)):
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


def generateKeys(number=10):
    for _ in range(number):
        priv = ec.generate_private_key(ec.SECP256K1(), default_backend())
        privValue = priv.private_numbers().private_value
        pub = priv.public_key().public_numbers()
        pubValue = Point(pub.x, pub.y, ECC_CURVE)
        yield (privValue, pubValue)



if __name__ == "__main__":
    message = b'Trang'
    keys = list(generateKeys())
    publicKeys = [k[1] for k in keys]
    privateKeys = [k[0] for k in keys]
    index = 3
    signature = sign(message, publicKeys, privateKeys[index], index)
    print(verify(message, publicKeys, signature))



