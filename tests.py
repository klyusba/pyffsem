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


def test_set():
    key = b'16byte secretkey'
    m = 256

    codec = FFSEM(key, max_num=m)
    v = set()
    for i in range(m):
        a = codec.encrypt(i)
        v.add(a)
        assert codec.decrypt(a) == i
    assert len(v) == m
