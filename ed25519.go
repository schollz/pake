package pake

import (
	"math/big"
	"sync"

	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
)

/*
utilities

- affine transformations derived from Section 3 of https://eprint.iacr.org/2008/522.pdf
*/

var p, _ = new(big.Int).SetString("57896044618658097711785492504343953926634992332820282019728792003956564819949", 10)

func swapEndianness(buf []byte) []byte {
	invariant := len(buf) - 1
	for i := 0; i < len(buf)/2; i++ {
		buf[i], buf[invariant-i] = buf[invariant-i], buf[i]
	}
	return buf
}

func fromAffine(x, y *big.Int) (*edwards25519.Point, error) {
	var X, Y, Z, T field.Element

	buf := make([]byte, 32)

	x.Mod(x, p)
	y.Mod(y, p)
	X.SetBytes(swapEndianness(x.FillBytes(buf)))
	Y.SetBytes(swapEndianness(y.FillBytes(buf)))
	Z.One()
	T.Multiply(&X, &Y)

	return new(edwards25519.Point).SetExtendedCoordinates(&X, &Y, &Z, &T)
}

func toAffine(point *edwards25519.Point) (*big.Int, *big.Int) {
	var X, Y, Z, _ = point.ExtendedCoordinates()
	var TX, TY, invZ field.Element
	var x, y big.Int

	invZ.Invert(Z)
	TX.Multiply(X, &invZ)
	x.SetBytes(swapEndianness(TX.Bytes()))
	x.Mod(&x, p)

	TY.Multiply(Y, &invZ)
	y.SetBytes(swapEndianness(TY.Bytes()))
	y.Mod(&y, p)

	return &x, &y
}

func coerceScalar(scalar []byte) *edwards25519.Scalar {
	k := new(big.Int).SetBytes(scalar)
	buf := make([]byte, 32)
	k.FillBytes(buf)
	S, _ := new(edwards25519.Scalar).SetBytesWithClamping(buf)
	return S
}

/* interface implementations */

type _ed25519 struct {
	P *big.Int
}

func (curve _ed25519) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	P1, _ := fromAffine(x1, y1)
	P2, _ := fromAffine(x2, y2)
	x3, y3 := toAffine(P1.Add(P1, P2))
	return x3, y3
}

func (curve _ed25519) ScalarBaseMult(scalar []byte) (*big.Int, *big.Int) {
	S := coerceScalar(scalar)
	P := new(edwards25519.Point).ScalarBaseMult(S)
	return toAffine(P)
}

func (curve _ed25519) ScalarMult(Bx, By *big.Int, scalar []byte) (*big.Int, *big.Int) {
	S := coerceScalar(scalar)
	P, _ := fromAffine(Bx, By)
	P.ScalarMult(S, P)
	return toAffine(P)
}

func (curve _ed25519) IsOnCurve(x, y *big.Int) bool {
	_, err := fromAffine(x, y)
	return err == nil
}

/* singleton initialization */

var ed25519 _ed25519
var initialize sync.Once

func initED25519() {
	ed25519.P = p
}

func ED25519() _ed25519 {
	initialize.Do(initED25519)
	return ed25519
}
