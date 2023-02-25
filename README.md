# pake

[![travis](https://travis-ci.org/schollz/pake.svg?branch=master)](https://travis-ci.org/schollz/pake) 
[![go report card](https://goreportcard.com/badge/github.com/schollz/pake)](https://goreportcard.com/report/github.com/schollz/pake)
[![Coverage Status](https://coveralls.io/repos/github/schollz/pake/badge.svg)](https://coveralls.io/github/schollz/pake)
[![godocs](https://godoc.org/github.com/schollz/pake?status.svg)](https://godoc.org/github.com/schollz/pake) 

This library will help you allow two parties to generate a mutual secret key by using a weak key that is known to both beforehand (e.g. via some other channel of communication). This is a simple API for an implementation of password-authenticated key exchange (PAKE). This protocol is derived from [Dan Boneh and Victor Shoup's cryptography book](https://crypto.stanford.edu/~dabo/cryptobook/BonehShoup_0_4.pdf) (pg 789, "PAKE2 protocol). I decided to create this library so I could use PAKE in my file-transfer utility, [croc](https://github.com/schollz/croc).


## Install

```
go get -u github.com/schollz/pake/v3
```

## Usage 

![Explanation of algorithm](https://i.imgur.com/s7oQWVP.png)

```golang
// both parties should have a weak key
weakKey := []byte{1, 2, 3}

// initialize A
A, err := pake.InitCurve(weakKey, 0, "siec")
if err != nil {
    panic(err)
}
// initialize B
B, err := pake.InitCurve(weakKey, 1, "siec")
if err != nil {
    panic(err)
}

// send A's stuff to B
err = B.Update(A.Bytes())
if err != nil {
    panic(err)
}

// send B's stuff to A
err = A.Update(B.Bytes())
if err != nil {
    panic(err)
}

// both P and Q now have strong key generated from weak key
kA, _ := A.SessionKey()
kB, _ := B.SessionKey()
fmt.Println(bytes.Equal(kA, kB))
// Output: true
```

When passing *P* and *Q* back and forth, the structure is being marshalled using `Bytes()`, which prevents any private variables from being accessed from either party.

Each function has an error. The error become non-nil when some part of the algorithm fails verification: i.e. the points are not along the elliptic curve, or if a hash from either party is not identified. If this happens, you should abort and start a new PAKE transfer as it would have been compromised. 

## Hard-coded elliptic curve points

The elliptic curve points are hard-coded to prevent an application from allowing users to supply their own points (which could be backdoors by choosing points with known discrete logs). Public points can be verified [via sage](https://sagecell.sagemath.org/?z=eJzNVl1v3NYRfReg_0DID9lFJPXOzP0M6gIklwyKvDhIH4wEtnE_60XWkrq7TiUU_u89lCzZaYOgbQq0fFhyybnnzsw5Z8i4273J7_c_1UP3vPvbh9OT05Nn3Xd_nMbTk28uf789_GV_lD_g0bfvY9nH4zbP27orqwtZn57cbPGAXxO77kuc2dyfiO9PFr8r6i66B4z17xgLEP_996ub7eXV9f7dar1etptwc9rttjcAH5dMVl_Pq5v1-Q_qnMKrdfesm77q7l4zwm5fC1ApnJ7Ep7R_ODtsaz57taAscEv-hmlPpyff4Z663agwea8UBxoHbyTYcbSOnARhr_u-V5ve6qF_SE_dKpr_5wcK_H_JBUJID7koQ8HINARLfqIx9DQHDj1TrwbrjVbT1POmd2yGEAYhM8vgB-1DQPxMoIGMpSDB0DS6KYgbyBoe1bCRYaBhVk6Mk83svWx4FD3TNGtD80bbwSiZlTo9-fr2IZcRO_pJ2cEprfQUxk2YZBoHaxkbDFpzGK32JEEZmQcoYvbs-9liid7IZuh70oOZnJvmyZnAfp5oM0LLPc9z7zeTiPaDjOSN7YE2zMFNbhIaeTLDxlrkcvfAEXlBI2zvfOhlGJXSZvS9mQfNo9vQsAnBz0ZrHYwLSM16cv08bMixkwkZj4CeHIdgUDBbrUZj1BAUydxvlLMkRkanvO3Z8chaeT9MQTsb5g1Za9CXq_-WXnpD3nrnZZh5DhYNnsdRkfazU6E3GwWuzBgGD15H7fppGOw8OJoCiUfq4Vc9Hc_Tq_XP7fviAuR88u-z7sUFG_vgRiJ0jJUPTEqMZe2dZRscehh00MpBL0YUOkNaNBkOSkhDpkbECgkaZZG2W2xvMBH2_yomuAgWMMwazXdWiWbNzCYoSwraI1Zai0W1h_vOZx2K2GW_CkUGsdFa5ytBgIVtcp5CczWAqXwf72pLEdxx8CZVbCs5KWOyM0UjUOXqi9cxZEOkY8qxCTlnvSKlW1Tl0ZUmZium-BglBqkuSU2pGKQckEvK1lBRNqmcjSTVrKRcJUtlh7SUTouj7oFsIleocSXOqNU1j0hbjZWotWrsnBJXPHGpSSSqpiNq09g6-Az1L3a4B9KtolmVW6XoWki-VleTji6rFipZXjJYepowImquOSXIxnpxqRlqpvtVAV3ILykIgvm5gsTrBwUhRcUKpAWLSw3midkFDA1SULXAW14Z5QLeBwzmLHxqQV3QnoNgtLA2jtF60gG2UAKJacd2oZqND1itYBjCXAEEEcvyetr_pp0tZhYiLTtrMC4DRMQg2eLaBxCiPJTOECukiUWQOuS9zA15VGNEgwNbiIJCZBehAQgemnQOdHrcySVmJ09qDIWqNabB-k1xa037kkutMBMEVJJXQM8EnorKkVRp1bZsUF_A4I-YbNWjVzWaBiM1W8mjGJezg4O8PKoVyiFu0VWWRRUaGq3K2FSleS6EFwWVkG1t1WNneAxuRqObwSj0btE6yg9wRuSK8MLRm-xrKVIzx9qe1Byjdzkyp-phK4ETE2VHtQmrWJxGgkWSZZ-iCwkehDs1VQVONUfxmL_c2BRIErPAZolGm4ocwImKyT2pHTS6UmFUzBDOtpkSavCp4YXABb5ovmkqqbAPkbTLNRSQQpJMU8lnpaJVSA3pONQciotacJ2DqlFV0_4DM0D7n38Obd_dXO-P3dt4eLvbpqf_-3hVrt8tAaW2rm2vypub6-3VcTWdH2otz9PZ2fqr05MOx0uA4cll21-_e5PujvWw-oh2eXgbabXEry_L9s_1cFytz8922-NxV8_WD6v_-na7q92f9u_rR7jlOO7vPvu3HPt6fL-_6qbL3bYd39yupssUD_VNu__cXK9erteXt3er9adF9TbXm-M_oLzsvsSEX6pq1_vux3p3PiH17lODLrfH-u6weiztZr-U3M4QuXz_4vThvHuxXP5CR77I--vMX6w_PJb276-mz1ZjTNxzcLk8X6Wze_Tl4QPsR9Ra2ODD67z7sXt-dt7ttujxx3XL6YEO4fXyMf3PePQb8P4ONjcVKw==&lang=sage&interacts=eJyLjgUAARUAuQ==) using hashes of `croc1` and `croc2`. The `ed25519` curve is not computable on sage, so two unique scalars based on the same seeds are generated and used to create valid points.

```python
all_curves = {}

# SIEC
K.<isqrt3> = QuadraticField(-3)
pi = 2^127 + 2^25 + 2^12 + 2^6 + (1 - isqrt3)/2
p = ZZ(pi.norm())

E = EllipticCurve(GF(p),[0,19]) # E: y^2 = x^3 + 19
all_curves["siec"] = E


# 521r1
S = 0xD09E8800291CB85396CC6717393284AAA0DA64BA
p = 0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
a = 0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC
b = 0x0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00
Gx= 0x00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66
Gy= 0x011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650
n = 0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409

E = EllipticCurve(GF(p),[a,b])
all_curves["P-521"] = E

# P-256
p = 115792089210356248762697446949407573530086143415290314195533631308867097853951
r = 115792089210356248762697446949407573529996955224135760342422259061068512044369
s = 0xc49d360886e704936a6678e1139d26b7819f7e90
c = 0x7efba1662985be9403cb055c75d4f7e0ce8d84a9c5114abcaf3177680104fa0d
b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
Gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
Gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5 

E = EllipticCurve(GF(p),[-3,b])
all_curves["P-256"] = E

# P-384
p = 39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319
r = 39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942643
s = 0xa335926aa319a27a1d00896a6773a4827acdac73
c = 0x79d1e655f868f02fff48dcdee14151ddb80643c1406d0ca10dfe6fc52009540a495e8042ea5f744f6e184667cc722483
b = 0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef
Gx = 0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7
Gy = 0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f

E = EllipticCurve(GF(p),[-3,b])
all_curves["P-384"] = E


import hashlib
import random

def find_point(E,seed=b""):
    X = int.from_bytes(hashlib.sha1(seed).digest(),"little")
    while True:
        try:
            return E.lift_x(E.base_field()(X)).xy()
        except:
            X += 1

for key,E in all_curves.items():
    print(f"key = {key}, P = {find_point(E,seed=b'croc2')}")
    print(f"key = {key}, P = {find_point(E,seed=b'croc1')}")
    
random.seed(b"croc2")
print("key = ed25519, k =", list(random.randbytes(32)))
random.seed(b"croc1")
print("key = ed25519, k =", list(random.randbytes(32)))
```

returns

```plain
key = siec, P = (793136080485469241208656611513609866400481671853, 18458907634222644275952014841865282643645472623913459400556233196838128612339)
key = siec, P = (1086685267857089638167386722555472967068468061489, 19593504966619549205903364028255899745298716108914514072669075231742699650911)
key = P-521, P = (793136080485469241208656611513609866400481671852, 4032821203812196944795502391345776760852202059010382256134592838722123385325802540879231526503456158741518531456199762365161310489884151533417829496019094620)
key = P-521, P = (1086685267857089638167386722555472967068468061489, 5010916268086655347194655708160715195931018676225831839835602465999566066450501167246678404591906342753230577187831311039273858772817427392089150297708931207)
key = P-256, P = (793136080485469241208656611513609866400481671852, 59748757929350367369315811184980635230185250460108398961713395032485227207304)
key = P-256, P = (1086685267857089638167386722555472967068468061489, 9157340230202296554417312816309453883742349874205386245733062928888341584123)
key = P-384, P = (793136080485469241208656611513609866400481671852, 7854890799382392388170852325516804266858248936799429260403044177981810983054351714387874260245230531084533936948596)
key = P-384, P = (1086685267857089638167386722555472967068468061489, 21898206562669911998235297167979083576432197282633635629145270958059347586763418294901448537278960988843108277491616)
key = ed25519, k = [147, 174, 26, 41, 144, 9, 197, 209, 211, 23, 183, 10, 15, 221, 81, 44, 165, 166, 218, 16, 201, 147, 208, 163, 102, 119, 115, 65, 250, 161, 104, 28]
key = ed25519, k = [126, 7, 4, 3, 86, 43, 21, 180, 33, 169, 146, 110, 150, 189, 241, 44, 168, 144, 217, 89, 164, 250, 175, 0, 230, 234, 212, 118, 100, 40, 175, 211]
```

which are the points used [in the code](pake.go#L77-L113).

## Contributing

Pull requests are welcome. Feel free to...

- Revise documentation
- Add new features
- Fix bugs
- Suggest improvements

## Thanks

Thanks [@tscholl2](https://github.com/tscholl2) for lots of implementation help, fixes, and developing the novel ["siec" curve](https://doi.org/10.1080/10586458.2017.1412371).


## License

MIT
