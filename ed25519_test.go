package pake

import (
	"math/big"
	"testing"

	"filippo.io/edwards25519"
)

// ed25519 base points
// from RFC 7748, Section 5.1: https://www.rfc-editor.org/rfc/rfc7748#section-5.1
var XP, _ = new(big.Int).SetString("15112221349535400772501151409588531511454012693041857206046113283949847762202", 10)
var YP, _ = new(big.Int).SetString("46316835694926478169428394003475163141307993866256225615783033603165251855960", 10)

// scalarmult test vectors, adjusted for clamping, based on
// https://github.com/FiloSottile/edwards25519/blob/v1.0.0/scalarmult_test.go#L17-L20
var (
	S        = []byte{219, 106, 114, 9, 174, 249, 155, 89, 69, 203, 201, 93, 92, 116, 234, 187, 78, 115, 103, 172, 182, 98, 62, 103, 187, 136, 13, 100, 248, 110, 12, 4}
	SBP, _   = new(edwards25519.Point).SetBytes([]byte{137, 149, 4, 21, 117, 34, 190, 68, 186, 167, 106, 255, 84, 31, 88, 190, 142, 225, 51, 241, 156, 188, 67, 140, 163, 110, 220, 162, 149, 156, 254, 43})
	DBX, DBY = toAffine(SBP)
)

func TestAffineConversion(t *testing.T) {
	P, _ := fromAffine(XP, YP)
	if P.Equal(edwards25519.NewGeneratorPoint()) != 1 {
		t.Error("expected affine transformation of basepoint to match")
	}

	GX, GY := toAffine(P)
	if GX.Cmp(XP) != 0 || GY.Cmp(YP) != 0 {
		t.Error("expected inverse affine transformation of basepoint to match")
	}
}

func TestAdd(t *testing.T) {
	IX, IY := toAffine(edwards25519.NewIdentityPoint())
	OX, OY := ED25519().Add(XP, YP, IX, IY)
	if XP.Cmp(OX) != 0 || YP.Cmp(OY) != 0 {
		t.Error("given output didn't match the expected")
	}
}

func TestScalarBaseMult(t *testing.T) {
	OX, OY := ED25519().ScalarBaseMult(S)
	if DBX.Cmp(OX) != 0 || DBY.Cmp(OY) != 0 {
		t.Error("given output didn't match the expected")
	}
}

func TestScalarMult(t *testing.T) {
	OX, OY := ED25519().ScalarMult(XP, YP, S)
	if DBX.Cmp(OX) != 0 || DBY.Cmp(OY) != 0 {
		t.Error("given output didn't match the expected")
	}
}

func TestIsOnCurve(t *testing.T) {
	if !ED25519().IsOnCurve(XP, YP) {
		t.Error("the basepoint must be on the curve but isn't")
	}
}
