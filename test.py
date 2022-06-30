from LB_crypto.math import *
from LB_crypto.SM4 import *
from LB_crypto.SM2 import *
from LB_crypto.SM3 import *
from LB_crypto.DS import *
from pycallgraph import PyCallGraph
from pycallgraph.output import GraphvizOutput
from pycallgraph import Config
from pycallgraph import GlobbingFilter


def main():
    print('---now test LB_crypto.math---')
    assert (is_prime(23333))
    #  assert (is_prime(1))
    #  assert (is_prime(2.33))
    print('is_prime ok!')

    assert (gcd(22224, 666) == 6)
    #  assert (gcd(3, 4) == 1)
    print('gcd ok!')

    assert (ex_gcd(3, 4) == (3, -2, 1))
    print('exgcd ok!')

    assert (fast_pow(2, 3, 5) == 3)
    print('fast_pow ok!')

    assert(get_inv(2, 11) == 6)
    print('get_inv ok!')

    a = [3, 5, 7]
    b = [2, 3, 2]
    assert (CRT(a, b) == 23)
    print('CRT ok!')

    assert (get_prime(11) == [2, 3, 5, 7, 11])
    print('get_prime ok!')

    assert (is_prime(generate_big_prime(233)))
    print('generate_big_prime ok!')

    print('---now test SM4---')
    s = SM4('557cfb9c1c78b048ae02bf5c88bc781a')
    s.SM4_CTR('test/SM4_CTR_test.txt', 0, 1)
    s.SM4_CTR('test/SM4_CTR_test1.txt.SM4_CTR', 0, 0)
    f1 = open('test/SM4_CTR_test.txt', 'rb')
    f2 = open('test/SM4_CTR_test1.txt', 'rb')
    while 1:
        c1 = f1.readline()
        c2 = f2.readline()
        assert c1 == c2
        if c1 == b'' or c2 == b'':
            break
    f1.close()
    f2.close()
    print('SM4_CTR ok!')

    s.SM4_OFB('test/SM4_OFB_test.txt', '1996aaaa1ba34b3cadc348a330e018e0', 6, 1)
    s.SM4_OFB('test/SM4_OFB_test1.txt.SM4_OFB', '1996aaaa1ba34b3cadc348a330e018e0', 6, 0)
    f1 = open('test/SM4_OFB_test.txt', 'rb')
    f2 = open('test/SM4_OFB_test1.txt', 'rb')
    while 1:
        c1 = f1.readline()
        c2 = f2.readline()
        assert c1 == c2
        if c1 == b'' or c2 == b'':
            break
    f1.close()
    f2.close()
    print('SM4_OFB ok!')

    print('---now test SM2---')
    s = SM2(
        4651790315172547324421427488787163462617155070424625206559,
        4598862935839736669809089888524020718089890230495750986117,
        596595254059354726415294216491069121288378220989917368769,
        192
    )
    res1 = s.SM2_encrypt(
        '0x656e6372797074696f6e207374616e64617264',
        1834968487600647824514410140269064362459199060214757221952,
        66972603455005182691778320537844117786519722001186891730,
        2989962154103254810804845704859775855103279169487815094090,
        4271922179579769876189437850048448302473410107141046597906,
        1380700738017179424849792545563870218395108139972515540149
    )
    assert res1 == '0x0423fc680b124294dfdf34dbe76e0c38d883de4d41fa0d4cf570cf14f20daf0c4d777f738d16b16824d31eefb9de31ee1fd1853f5a88376c54389d1239640410d0b274c0a6a921fc70bfc1046001f50fe6ccad02cb83a1d73b777c97a47773de93579613'
    res2 = s.SM2_decrypt(
        '0x0423fc680b124294dfdf34dbe76e0c38d883de4d41fa0d4cf570cf14f20daf0c4d777f738d16b16824d31eefb9de31ee1fbc104da135491c409810c55bd04ffb91a67b51a8462664fe2e1ed74514ee1f75b422d1a0ade2a367a09ab5b6d91c432ee40f5c',
        2170891990532084219830703229170485512351379721740652731133
    )
    assert res2 == '0x8fb1189c40e047dcfe3f711c02a8525757df5'
    print('SM2 ok!')

    print('---now test Digital Signature---')
    s = ElGamal_DS(
        83140518507955175410602407511153607756780169990216441342082776374890392081747,
        8392920438247434999773335902924584146404475752662517131542309831954456089299
    )
    s1, s2 = s.Sign(
        32818439577509743415414497918740253742885474112097294116297007923828551310368,
        32159491633952294478443526426159016616288628842915781664018859095939957945461,
        '是 谁 憋 疯 了'
    )
    assert s.Vrfy(
        fast_pow(s.g, 32818439577509743415414497918740253742885474112097294116297007923828551310368, s.p),
        s1,
        s2,
        '是 谁 憋 疯 了'
    )
    print('ElGamal Digital Sign ok!')

    print('---now test SM3---')
    res = SM3().hash_get('this is the first SM3 testcase.')
    assert res == '1c7d1fcf91f37a2ecb8877b5896d3474010784a75cdb1d392375029c4469e653'
    print('SM3 ok!')


if __name__ == '__main__':
    config = Config()
    graphviz = GraphvizOutput()
    graphviz.output_file = 'graph.png'
    with PyCallGraph(output=graphviz, config=config):
        main()