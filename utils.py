
from LinkableRingSignature.constants import INTEGER_BYTES


def bytes2Int(bs):
    """
    convert bytes array to int
    :param bs: bytes
    :return: an integer
    """
    return int.from_bytes(bs, 'big')

def int2bytes(number):
    """
    convert an int to bytes
    :param number: integer
    :return: bytes
    """
    return int.to_bytes(number, INTEGER_BYTES, 'big')


def pointTobytes(point):
    """
    convert EC point to bytes
    :param point:  EC point
    :return: bytes
    """
    x = int2bytes(point[0])
    y = int2bytes(point[1])
    return x+y


