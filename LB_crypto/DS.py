from LB_crypto.SM3 import SM3
from LB_crypto.math import fast_pow, get_inv


class ElGamal_DS:
    p = 0
    g = 0

    def __init__(self, p, g):
        self.p = p
        self.g = g

    def Sign(self, x, k, M):
        m = int(SM3().hash_get(M), 16)
        S1 = fast_pow(self.g, k, self.p)
        S2 = (m - x * S1) * get_inv(k, self.p - 1) % (self.p - 1)
        return S1, S2

    def Vrfy(self, y, s1, s2, M):
        m = int(SM3().hash_get(M), 16)
        V1 = fast_pow(self.g, m, self.p)
        V2 = fast_pow(y, s1, self.p) * fast_pow(s1, s2, self.p) % self.p
        return V1 == V2
