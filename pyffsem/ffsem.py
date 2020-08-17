from Crypto.Cipher import AES
import math
import warnings


class FFSEM:
    """
    Spies, Terence. "Feistel finite set encryption mode."
    https://csrc.nist.gov/csrc/media/projects/block-cipher-techniques/documents/bcm/proposed-modes/ffsem/ffsem-spec.pdf
    """
    def __init__(self, key: bytes, max_num: int, rounds: int = 10):
        self.cipher = AES.new(key, AES.MODE_ECB)
        self._base = math.floor(math.log2(max_num) / 2)
        self.max_num = 1 << 2*self._base
        if self.max_num != max_num:
            warnings.warn('max_num was truncated to nearest power of 4')
        self.rounds = rounds

    def _pfr(self, a: int) -> int:
        b = a.to_bytes(self.cipher.block_size, byteorder='big', signed=False)
        return int.from_bytes(self.cipher.encrypt(b), byteorder='big', signed=False)

    def encrypt(self, a: int) -> int:
        if a > self.max_num:
            raise ValueError(f'Value must be less then {self.max_num}')

        l, r = divmod(a, 1 << self._base)
        for i in range(self.rounds):
            b = (r << self.cipher.block_size * 8 - self._base) + (i + 1)
            e = self._pfr(b)
            l, r = r, l ^ (e >> self.cipher.block_size * 8 - self._base)
        return (l << self._base) + r

    def decrypt(self, a: int) -> int:
        if a > self.max_num:
            raise ValueError(f'Value must be less then {self.max_num}')

        l, r = divmod(a, 1 << self._base)
        for i in range(self.rounds, 0, -1):
            b = (l << self.cipher.block_size * 8 - self._base) + i
            e = self._pfr(b)
            r, l = l, r ^ (e >> self.cipher.block_size * 8 - self._base)
        return (l << self._base) + r
