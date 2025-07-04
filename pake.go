package pake

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"filippo.io/edwards25519"
	"github.com/tscholl2/siec"
)

// EllipticCurve is a general curve which allows other
// elliptic curves to be used with PAKE.
type EllipticCurve interface {
	Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int)
	ScalarBaseMult(k []byte) (*big.Int, *big.Int)
	ScalarMult(Bx, By *big.Int, k []byte) (*big.Int, *big.Int)
	IsOnCurve(x, y *big.Int) bool
}

// Edwards25519Curve implements EllipticCurve interface for Edwards25519
// It stores the full 32-byte Edwards25519 point in the x coordinate
// and uses y coordinate to indicate negation for subtraction
type Edwards25519Curve struct{}

func (e *Edwards25519Curve) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	p1, err1 := (&edwards25519.Point{}).SetBytes(ed25519PointFromBigInts(x1, y1))
	p2, err2 := (&edwards25519.Point{}).SetBytes(ed25519PointFromBigInts(x2, y2))
	if err1 != nil || err2 != nil {
		return big.NewInt(0), big.NewInt(0)
	}
	result := (&edwards25519.Point{}).Add(p1, p2)
	return ed25519PointToBigInts(result.Bytes())
}

// Subtract performs point subtraction for Edwards25519
func (e *Edwards25519Curve) Subtract(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	p1, err1 := (&edwards25519.Point{}).SetBytes(ed25519PointFromBigInts(x1, y1))
	p2, err2 := (&edwards25519.Point{}).SetBytes(ed25519PointFromBigInts(x2, y2))
	if err1 != nil || err2 != nil {
		return big.NewInt(0), big.NewInt(0)
	}
	result := (&edwards25519.Point{}).Subtract(p1, p2)
	return ed25519PointToBigInts(result.Bytes())
}

func (e *Edwards25519Curve) ScalarBaseMult(k []byte) (*big.Int, *big.Int) {
	key := normalizeScalar(k)
	scalar, err := (&edwards25519.Scalar{}).SetBytesWithClamping(key)
	if err != nil {
		return big.NewInt(0), big.NewInt(0)
	}
	point := (&edwards25519.Point{}).ScalarBaseMult(scalar)
	return ed25519PointToBigInts(point.Bytes())
}

func (e *Edwards25519Curve) ScalarMult(Bx, By *big.Int, k []byte) (*big.Int, *big.Int) {
	point, err1 := (&edwards25519.Point{}).SetBytes(ed25519PointFromBigInts(Bx, By))
	if err1 != nil {
		return big.NewInt(0), big.NewInt(0)
	}
	key := normalizeScalar(k)
	scalar, err2 := (&edwards25519.Scalar{}).SetBytesWithClamping(key)
	if err2 != nil {
		return big.NewInt(0), big.NewInt(0)
	}
	result := (&edwards25519.Point{}).ScalarMult(scalar, point)
	return ed25519PointToBigInts(result.Bytes())
}

func (e *Edwards25519Curve) IsOnCurve(x, y *big.Int) bool {
	_, err := (&edwards25519.Point{}).SetBytes(ed25519PointFromBigInts(x, y))
	return err == nil
}

// normalizeScalar ensures the scalar is exactly 32 bytes
func normalizeScalar(k []byte) []byte {
	key := make([]byte, 32)
	if len(k) >= 32 {
		copy(key, k[:32])
	} else {
		copy(key[32-len(k):], k)
	}
	return key
}

// ed25519PointFromBigInts converts big.Int coordinates back to Edwards25519 point bytes
func ed25519PointFromBigInts(x, y *big.Int) []byte {
	// The point is stored entirely in x, y is ignored for Edwards25519
	bytes := make([]byte, 32)
	xBytes := x.Bytes()
	if len(xBytes) <= 32 {
		copy(bytes[32-len(xBytes):], xBytes)
	}
	return bytes
}

// ed25519PointToBigInts converts Edwards25519 point bytes to big.Int coordinates
func ed25519PointToBigInts(pointBytes []byte) (*big.Int, *big.Int) {
	if len(pointBytes) != 32 {
		return big.NewInt(0), big.NewInt(0)
	}
	// Store the entire point in x coordinate, y is always 0
	x := new(big.Int).SetBytes(pointBytes)
	y := big.NewInt(0)
	return x, y
}

// Pake keeps public and private variables by
// only transmitting between parties after marshaling.
//
// This method follows
// https://crypto.stanford.edu/~dabo/cryptobook/BonehShoup_0_4.pdf
// Figure 21/15
// http://www.lothar.com/~warner/MagicWormhole-PyCon2016.pdf
// Slide 11
type Pake struct {
	// Public variables
	Role   int
	Uᵤ, Uᵥ *big.Int
	Vᵤ, Vᵥ *big.Int
	Xᵤ, Xᵥ *big.Int
	Yᵤ, Yᵥ *big.Int

	// Private variables
	curve      EllipticCurve
	P          *big.Int // the order of the underlying field
	Pw         []byte
	Vpwᵤ, Vpwᵥ *big.Int
	Upwᵤ, Upwᵥ *big.Int
	Aα         []byte
	Aαᵤ, Aαᵥ   *big.Int
	Zᵤ, Zᵥ     *big.Int
	K          []byte
}

// Public returns the public variables of Pake
func (p *Pake) Public() *Pake {
	return &Pake{
		Role: p.Role,
		Uᵤ:   p.Uᵤ,
		Uᵥ:   p.Uᵥ,
		Vᵤ:   p.Vᵤ,
		Vᵥ:   p.Vᵥ,
		Xᵤ:   p.Xᵤ,
		Xᵥ:   p.Xᵥ,
		Yᵤ:   p.Yᵤ,
		Yᵥ:   p.Yᵥ,
	}
}

// AvailableCurves returns available curves
func AvailableCurves() []string {
	return []string{"p521", "p256", "p384", "siec", "ed25519"}
}

// InitCurve will take the secret weak passphrase (pw) to initialize
// the points on the elliptic curve. The role is set to either
// 0 for the sender or 1 for the recipient.
// The curve can be siec,  p521, p256, p384
func initCurve(curve string) (ellipticCurve EllipticCurve, P *big.Int, Ux *big.Int, Uy *big.Int, Vx *big.Int, Vy *big.Int, err error) {
	switch curve {
	case "p521":
		ellipticCurve = elliptic.P521()
		Ux, _ = new(big.Int).SetString("793136080485469241208656611513609866400481671852", 10)
		Uy, _ = new(big.Int).SetString("4032821203812196944795502391345776760852202059010382256134592838722123385325802540879231526503456158741518531456199762365161310489884151533417829496019094620", 10)
		Vx, _ = new(big.Int).SetString("1086685267857089638167386722555472967068468061489", 10)
		Vy, _ = new(big.Int).SetString("5010916268086655347194655708160715195931018676225831839835602465999566066450501167246678404591906342753230577187831311039273858772817427392089150297708931207", 10)
		P = elliptic.P521().Params().P
	case "p256":
		ellipticCurve = elliptic.P256()
		Ux, _ = new(big.Int).SetString("793136080485469241208656611513609866400481671852", 10)
		Uy, _ = new(big.Int).SetString("59748757929350367369315811184980635230185250460108398961713395032485227207304", 10)
		Vx, _ = new(big.Int).SetString("1086685267857089638167386722555472967068468061489", 10)
		Vy, _ = new(big.Int).SetString("9157340230202296554417312816309453883742349874205386245733062928888341584123", 10)
		P = elliptic.P256().Params().P
	case "p384":
		ellipticCurve = elliptic.P384()
		Ux, _ = new(big.Int).SetString("793136080485469241208656611513609866400481671852", 10)
		Uy, _ = new(big.Int).SetString("7854890799382392388170852325516804266858248936799429260403044177981810983054351714387874260245230531084533936948596", 10)
		Vx, _ = new(big.Int).SetString("1086685267857089638167386722555472967068468061489", 10)
		Vy, _ = new(big.Int).SetString("21898206562669911998235297167979083576432197282633635629145270958059347586763418294901448537278960988843108277491616", 10)
		P = elliptic.P384().Params().P
	case "siec":
		ellipticCurve = siec.SIEC255()
		Ux, _ = new(big.Int).SetString("793136080485469241208656611513609866400481671853", 10)
		Uy, _ = new(big.Int).SetString("18458907634222644275952014841865282643645472623913459400556233196838128612339", 10)
		Vx, _ = new(big.Int).SetString("1086685267857089638167386722555472967068468061489", 10)
		Vy, _ = new(big.Int).SetString("19593504966619549205903364028255899745298716108914514072669075231742699650911", 10)
		P = siec.SIEC255().Params().P
	case "ed25519":
		ellipticCurve = &Edwards25519Curve{}
		// Use fixed valid Edwards25519 points generated from "croc1" and "croc2" seeds
		Ux, _ = new(big.Int).SetString("41821174510521985817056358996007359290163947216650231187782646151092828043509", 10)
		Uy, _ = new(big.Int).SetString("0", 10)
		Vx, _ = new(big.Int).SetString("1456941786990260824647297143563623381366314063537015067473110401627488371271", 10)
		Vy, _ = new(big.Int).SetString("0", 10)
		// 2^255 - 19
		P, _ = new(big.Int).SetString("57896044618658097711785492504343953926634992332820282019728792003956564819949", 10)
	default:
		err = errors.New("no such curve")
		return
	}
	if err == nil {
		if !ellipticCurve.IsOnCurve(Ux, Uy) {
			err = fmt.Errorf("Ux/Uy not on curve")
		}
		if !ellipticCurve.IsOnCurve(Vx, Vy) {
			err = fmt.Errorf("Vx/Vy not on curve")
		}
	}

	return
}

// Init will take the secret weak passphrase (pw) to initialize
// the points on the elliptic curve. The role is set to either
// 0 for the sender or 1 for the recipient.
// The curve can be any elliptic curve.
func InitCurve(pw []byte, role int, curve string) (p *Pake, err error) {
	p = new(Pake)
	p.curve, p.P, p.Uᵤ, p.Uᵥ, p.Vᵤ, p.Vᵥ, err = initCurve(curve)
	if err != nil {
		return
	}
	p.Pw = pw
	if role == 1 {
		p.Role = 1
	} else {
		p.Role = 0

		// STEP: A computes X
		p.Vpwᵤ, p.Vpwᵥ = p.curve.ScalarMult(p.Vᵤ, p.Vᵥ, p.Pw)
		p.Upwᵤ, p.Upwᵥ = p.curve.ScalarMult(p.Uᵤ, p.Uᵥ, p.Pw)
		p.Aα = make([]byte, 32) // randomly generated secret
		_, err = rand.Read(p.Aα)
		if err != nil {
			return
		}
		p.Aαᵤ, p.Aαᵥ = p.curve.ScalarBaseMult(p.Aα)
		p.Xᵤ, p.Xᵥ = p.curve.Add(p.Upwᵤ, p.Upwᵥ, p.Aαᵤ, p.Aαᵥ) // "X"
		// now X should be sent to B
	}
	return
}

// Bytes just marshalls the PAKE structure so that
// private variables are hidden.
func (p *Pake) Bytes() (b []byte) {
	if p == nil {
		panic("pake is not initialized")
	}
	b, err := json.Marshal(p.Public())
	if err != nil {
		panic(err)
	}
	return
}

// Update will update itself with the other parties
// PAKE and automatically determine what stage
// and what to generate.
func (p *Pake) Update(qBytes []byte) (err error) {
	if p == nil {
		err = fmt.Errorf("pake is not initialized")
		return
	}
	var q *Pake
	err = json.Unmarshal(qBytes, &q)
	if err != nil {
		return
	}
	if p.Role == q.Role {
		err = errors.New("can't have its own role")
		return
	}

	if p.Role == 1 {
		// copy over public variables
		p.Xᵤ, p.Xᵥ = q.Xᵤ, q.Xᵥ

		// confirm that X is on curve
		if !p.curve.IsOnCurve(p.Xᵤ, p.Xᵥ) {
			err = errors.New("X values not on curve")
			return
		}

		// STEP: B computes Y
		p.Vpwᵤ, p.Vpwᵥ = p.curve.ScalarMult(p.Vᵤ, p.Vᵥ, p.Pw)
		p.Upwᵤ, p.Upwᵥ = p.curve.ScalarMult(p.Uᵤ, p.Uᵥ, p.Pw)
		p.Aα = make([]byte, 32) // randomly generated secret
		rand.Read(p.Aα)
		p.Aαᵤ, p.Aαᵥ = p.curve.ScalarBaseMult(p.Aα)
		p.Yᵤ, p.Yᵥ = p.curve.Add(p.Vpwᵤ, p.Vpwᵥ, p.Aαᵤ, p.Aαᵥ) // "Y"
		// STEP: B computes Z
		if ed25519Curve, ok := p.curve.(*Edwards25519Curve); ok {
			// For Edwards25519, use proper subtraction
			p.Zᵤ, p.Zᵥ = ed25519Curve.Subtract(p.Xᵤ, p.Xᵥ, p.Upwᵤ, p.Upwᵥ)
		} else {
			// For other curves, use the original negation method
			v := new(big.Int).Neg(p.Upwᵥ)
			v.Mod(v, p.P)
			p.Zᵤ, p.Zᵥ = p.curve.Add(p.Xᵤ, p.Xᵥ, p.Upwᵤ, v)
		}
		p.Zᵤ, p.Zᵥ = p.curve.ScalarMult(p.Zᵤ, p.Zᵥ, p.Aα)
		// STEP: B computes k
		// H(pw,id_P,id_Q,X,Y,Z)
		HB := sha256.New()
		HB.Write(p.Pw)
		HB.Write(p.Xᵤ.Bytes())
		HB.Write(p.Xᵥ.Bytes())
		HB.Write(p.Yᵤ.Bytes())
		HB.Write(p.Yᵥ.Bytes())
		HB.Write(p.Zᵤ.Bytes())
		HB.Write(p.Zᵥ.Bytes())
		// STEP: B computes k
		p.K = HB.Sum(nil)
	} else {
		p.Yᵤ, p.Yᵥ = q.Yᵤ, q.Yᵥ

		// confirm that Y is on curve
		if !p.curve.IsOnCurve(p.Yᵤ, p.Yᵥ) {
			err = errors.New("Y values not on curve")
			return
		}

		// STEP: A computes Z
		if ed25519Curve, ok := p.curve.(*Edwards25519Curve); ok {
			// For Edwards25519, use proper subtraction
			p.Zᵤ, p.Zᵥ = ed25519Curve.Subtract(p.Yᵤ, p.Yᵥ, p.Vpwᵤ, p.Vpwᵥ)
		} else {
			// For other curves, use the original negation method
			v := new(big.Int).Neg(p.Vpwᵥ)
			v.Mod(v, p.P)
			p.Zᵤ, p.Zᵥ = p.curve.Add(p.Yᵤ, p.Yᵥ, p.Vpwᵤ, v)
		}
		p.Zᵤ, p.Zᵥ = p.curve.ScalarMult(p.Zᵤ, p.Zᵥ, p.Aα)
		// STEP: A computes k
		// H(pw,id_P,id_Q,X,Y,Z)
		HA := sha256.New()
		HA.Write(p.Pw)
		HA.Write(p.Xᵤ.Bytes())
		HA.Write(p.Xᵥ.Bytes())
		HA.Write(p.Yᵤ.Bytes())
		HA.Write(p.Yᵥ.Bytes())
		HA.Write(p.Zᵤ.Bytes())
		HA.Write(p.Zᵥ.Bytes())
		p.K = HA.Sum(nil)
	}
	return
}

// SessionKey is returned, unless it is not generated
// in which is returns an error. This function does
// not check if it is verifies.
func (p *Pake) SessionKey() ([]byte, error) {
	var err error
	if p == nil {
		err = fmt.Errorf("pake is not initialized")
	}
	if p.K == nil {
		err = errors.New("session key not generated")
	}
	return p.K, err
}

// HaveSessionKey returns whether a session key has been generated
func (p *Pake) HaveSessionKey() bool {
	if p == nil {
		return false
	}
	return p.K != nil
}
