from pyffsem import FFSEM


def test1():
    a = 3333_3333_3333_3333
    m = 9999_9999_9999_9999
    key = b'16byte secretkey'
    codec = FFSEM(key, max_num=m)
    r = codec.encrypt(a)
    assert r <= m
    b = codec.decrypt(r)
    assert a == b
