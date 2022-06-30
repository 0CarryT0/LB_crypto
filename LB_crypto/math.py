import random


def is_prime(N):
    """
    check if N is a prime or not.
    use Miller Rabin algorithm.
    :param N: int
    :return: bool
    """
    if N <= 1 or type(N) != type(1):
        raise ValueError
    if N == 2:
        return True
    t = N - 1
    k = 0
    while (t & 1) == 0:
        t >>= 1
        k += 1
    for i in range(30):
        a = random.randint(2, N - 1)
        now = fast_pow(a, t, N)
        if now == 1:
            continue
        flag = 0
        for j in range(k):
            if now == N - 1:
                flag = 1
                break
            now = fast_pow(now, 2, N)
        if flag == 0:
            return False
    return True


def gcd(a, b):
    """
    calculate gcd(a, b)
    :param a: int
    :param b: int
    :return: ans -> int
    """
    if type(a) != type(b) != type(1):
        raise ValueError
    if b == 0:
        return a
    return gcd(b, a % b)


def ex_gcd(a, b):
    """
    solve ax + by = g
    :param a: int
    :param b: int
    :return: [x, y, g] -> [int, int, int]
    """
    if type(a) != type(b) != type(1):
        raise ValueError

    ta, tb = a, b
    x1, y1 = 1, 0
    x2, y2 = 0, 1
    while b:
        x1 -= x2 * (a // b)
        y1 -= y2 * (a // b)
        a = a % b
        a, b = b, a
        x1, y1, x2, y2 = x2, y2, x1, y1
    x, y, g = x1, y1, a
    if g < 0:
        x, y, g = -x, -y, -g
    y += x // (tb // g) * (ta // g)
    x %= (tb // g)
    if x < 0:
        if tb > 0:
            x += tb // g
            y -= ta // g
        else:
            x -= tb // g
            y += ta // g
    return x, y, g


def fast_pow(a, b, c):
    """
    calculate a ^ b % c
    :param a: int
    :param b: int
    :param c: int
    :return: ans -> int
    """
    if type(a) != type(b) != type(c) != type(1):
        raise ValueError

    ans = 1
    while b:
        if b & 1:
            ans = ans * a % c
        a = a * a % c
        b >>= 1
    return ans


def get_inv(a, m):
    """
    calculate inv(a) % m
    :param a: int
    :param m: int
    :return: inv -> int
    """
    if type(a) != type(m) != type(1):
        raise ValueError

    inv = ex_gcd(a, m)[0]
    return inv


def CRT(a, b):
    """
    CRT
    ans = bi mod ai
    :param a: list[int]
    :param b: list[int]
    :return: ans -> int
    """
    if type(a) != type(b) != type([1]):
        raise ValueError

    m = 1
    for ele in a:
        m *= ele
    ans = 0
    for i in range(0, len(b)):
        ans += b[i] * m // a[i] * get_inv(m // a[i], a[i])
    ans %= m
    if ans == 0:
        ans += m
    return ans


def get_prime(n):
    """
    get prime int [2, n]
    :param n: int
    :return: list[int]
    """
    if type(n) != type(1):
        raise ValueError
    v = []
    prime = []
    for i in range(1, n + 2):
        v.append(0)
    for i in range(2, n + 1):
        if v[i] == 0:
            prime.append(i)
            v[i] = i
        for x in prime:
            if x > v[i] or x * i > n:
                break
            v[x * i] = x
    return prime


def generate_big_prime(n):
    """
    generate a prime about n bit
    :param n:
    :return: a prime
    """
    if type(n) != type(1):
        raise ValueError
    x = (1 << n) + 1
    while 1:
        if is_prime(x):
            break
        x += 2
    return x
