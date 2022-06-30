from LB_crypto.math import get_inv
from LB_crypto.SM3 import SM3


class SM2:
    # y^2 = x^3 + ax + b (mod p)
    a = 0
    b = 0
    p = 0
    Par = 0

    def __init__(self, p, a, b, Par):
        self.a = a
        self.b = b
        self.p = p
        self.Par = Par

    def __ECC_calc(self, Ax, Ay, Bx, By):
        """
        :param Ax: A的x坐标
        :param Ay: A的y坐标
        :param Bx: B的x坐标
        :param By: B的y坐标
        :return: Rx, Ry:result
        """
        if Ax == 0 and Ay == 0:
            return Bx, By
        if Bx == 0 and By == 0:
            return Ax, Ay
        if Ax == Bx and Ay != By:
            return 0, 0
        if Ax == Bx and Ay == By:
            lam = (3 * Ax * Ax % self.p + self.a) * get_inv(2 * Ay, self.p) % self.p
        else:
            lam = (Ay - By) * get_inv(Ax - Bx, self.p) % self.p
        Rx = (lam * lam % self.p - Ax - Bx) % self.p
        Ry = (lam * (Ax - Rx) % self.p - Ay) % self.p
        return Rx, Ry

    def __ECC_add(self, Ax, Ay, Bx, By):
        return self.__ECC_calc(Ax, Ay, Bx, By)

    def __ECC_minus(self, Ax, Ay, Bx, By):
        return self.__ECC_calc(Ax, Ay, Bx, self.p - By)

    def __ECC_mul(self, k, Ax, Ay):
        tk = k
        Rx, Ry = 0, 0
        tAx, tAy = Ax, Ay
        while tk:
            if tk & 1:
                Rx, Ry = self.__ECC_calc(Rx, Ry, tAx, tAy)
            tk >>= 1
            tAx, tAy = self.__ECC_calc(tAx, tAy, tAx, tAy)
        return Rx, Ry

    def __ECC_div(self, k, Bx, By):
        tk = get_inv(k, self.p)
        Rx, Ry = 0, 0
        tBx, tBy = Bx, By
        while tk:
            if tk & 1:
                Rx, Ry = self.__ECC_calc(Rx, Ry, tBx, tBy)
            tk >>= 1
            tBx, tBy = self.__ECC_calc(tBx, tBy, tBx, tBy)
        return Rx, Ry

    def __KDF(self, Z, klen):
        K = ''
        for ct in range(1, klen // 256 + (klen % 256 != 0) + 1):
            K += SM3().hash_get(hex(Z << 32 | ct)[2:].zfill(self.Par // 2 + 8))
        K = K[0:klen // 4]
        return int(K, 16)

    def SM2_encrypt(self, m, Gx, Gy, PBx, PBy, k):
        """
        :param m: message hex
        :param Gx:
        :param Gy:
        :param PBx:
        :param PBy:
        :param k: random number
        :return: ciphertext hex
        """
        if m[:2] == '0x':
            m = m[2:]
        Par = ((self.Par - 1) // 4 + 1) * 4
        klen = len(m) * 4
        C1x, C1y = self.__ECC_mul(k, Gx, Gy)
        C1 = (C1x << Par | C1y)

        x2, y2 = self.__ECC_mul(k, PBx, PBy)
        Z = x2 << Par | y2
        t = self.__KDF(Z, klen)
        M = int(m, 16)
        C2 = M ^ t

        tmp = (x2 << (Par + klen)) | (M << Par) | y2
        if tmp == 0:
            C3 = 0
        else:
            C3 = int(SM3().hash_get(hex(tmp)), 16)
        return "0x04" + hex((C1 << (klen + 256)) | (C2 << 256) | C3)[2:].zfill((klen + 256) // 4 + Par // 2)

    def SM2_decrypt(self, c, dB):
        """
        :param c: ciphertext hex
        :param dB: private key
        :return: message hex
        """
        c = c[4:]
        Par = ((self.Par - 1) // 4 + 1) * 4
        klen = len(c) * 4 - 2 * Par - 256
        if klen % 4 != 0:
            klen -= 2
        c = int(c, 16)
        C1x, C1y = c >> (Par + klen + 256), c >> (klen + 256) & ((1 << Par) - 1)
        x2, y2 = self.__ECC_mul(dB, C1x, C1y)
        C2 = c >> 256 & ((1 << klen) - 1)
        Z = x2 << Par | y2
        t = self.__KDF(Z, klen)
        M = "0x{:x}".format(C2 ^ t)
        return M
