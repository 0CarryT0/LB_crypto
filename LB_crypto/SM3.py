class SM3:
    IV = 0x7380166f4914b2b9172442d7da8a0600a96f30bc163138aae38dee4db0fb0e4e
    T1 = 0x79cc4519
    T2 = 0x7a879d8a
    MOD = 0xffffffff

    def __FF1(self, x, y, z):
        return x ^ y ^ z

    def __FF2(self, x, y, z):
        return (x & y) | (x & z) | (y & z)

    def __GG1(self, x, y, z):
        return x ^ y ^ z

    def __GG2(self, x, y, z):
        return (x & y) | ((self.MOD - x) & z)

    def __change_s(self, s):
        Y = []
        ls = len(s)
        if ls % 64 < 56:
            s += b'\x80'
            for i in range(55 - ls % 64):
                s += b'\x00'
        else:
            s += b'\x80'
            for i in range(55 - ls % 64 + 64):
                s += b'\x00'
        ls = ls * 8
        for i in range(8):
            s += bytes([(ls >> ((7 - i) * 8)) & 255])
        cnt = 0
        sum = 0
        for x in s:
            sum = sum << 8 | x
            cnt += 1
            if cnt == 64:
                Y.append(sum)
                sum = 0
                cnt = 0
        return Y

    def __left_shift(self, x, l, lx):
        return ((x << l) | (x >> (lx - l))) & ((1 << lx) - 1)

    def __P0(self, x):
        return x ^ self.__left_shift(x, 9, 32) ^ self.__left_shift(x, 17, 32)

    def __P1(self, x):
        return x ^ self.__left_shift(x, 15, 32) ^ self.__left_shift(x, 23, 32)

    def __generate_w(self, y):
        w = []
        for i in range(16):
            w.append(y >> ((15 - i) * 32) & self.MOD)
        for i in range(16, 68):
            w.append(self.__P1(w[i - 16] ^ w[i - 9] ^ self.__left_shift(w[i - 3], 15, 32)) ^ self.__left_shift(w[i - 13], 7, 32) ^ w[i - 6])
        return w

    def __generate_wt(self, w):
        wt = []
        for i in range(64):
            wt.append(w[i] ^ w[i + 4])
        return wt

    def __merge(self, A, B, C, D, E, F, G, H):
        return A << (32 * 7) | B << (32 * 6) | C << (32 * 5) | D << (32 * 4) | E << (32 * 3) | F << (32 * 2) | G << 32 | H

    def hash_get(self, m):
        s = m.encode('UTF-8')
        Y = self.__change_s(s)
        V = self.IV
        for y in Y:
            W = self.__generate_w(y)
            Wt = self.__generate_wt(W)
            A = V >> (32 * 7)
            B = V >> (32 * 6) & self.MOD
            C = V >> (32 * 5) & self.MOD
            D = V >> (32 * 4) & self.MOD
            E = V >> (32 * 3) & self.MOD
            F = V >> (32 * 2) & self.MOD
            G = V >> (32 * 1) & self.MOD
            H = V & self.MOD
            for j in range(16):
                SS1 = self.__left_shift((self.__left_shift(A, 12, 32) + E + self.__left_shift(self.T1, j, 32)) & self.MOD, 7, 32)
                SS2 = SS1 ^ self.__left_shift(A, 12, 32)
                TT1 = (self.__FF1(A, B, C) + D + SS2 + Wt[j]) & self.MOD
                TT2 = (self.__GG1(E, F, G) + H + SS1 + W[j]) & self.MOD
                D = C
                C = self.__left_shift(B, 9, 32)
                B = A
                A = TT1
                H = G
                G = self.__left_shift(F, 19, 32)
                F = E
                E = self.__P0(TT2)

            for j in range(16, 64):
                SS1 = self.__left_shift((self.__left_shift(A, 12, 32) + E + self.__left_shift(self.T2, j % 32, 32)) & self.MOD, 7, 32)
                SS2 = SS1 ^ self.__left_shift(A, 12, 32)
                TT1 = (self.__FF2(A, B, C) + D + SS2 + Wt[j]) & self.MOD
                TT2 = (self.__GG2(E, F, G) + H + SS1 + W[j]) & self.MOD
                D = C
                C = self.__left_shift(B, 9, 32)
                B = A
                A = TT1
                H = G
                G = self.__left_shift(F, 19, 32)
                F = E
                E = self.__P0(TT2)
            V = self.__merge(A, B, C, D, E, F, G, H) ^ V
        return hex(V)[2:].zfill(64)
