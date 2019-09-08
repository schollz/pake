package pake

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math/big"
	"time"

	"github.com/tscholl2/siec"
	"golang.org/x/crypto/bcrypt"
)

// EllipticCurve is a general curve which allows other
// elliptic curves to be used with PAKE.
type EllipticCurve interface {
	Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int)
	ScalarBaseMult(k []byte) (*big.Int, *big.Int)
	ScalarMult(Bx, By *big.Int, k []byte) (*big.Int, *big.Int)
	IsOnCurve(x, y *big.Int) bool
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
	Role     int
	Uᵤ, Uᵥ   *big.Int
	Vᵤ, Vᵥ   *big.Int
	Xᵤ, Xᵥ   *big.Int
	Yᵤ, Yᵥ   *big.Int
	HkA, HkB []byte

	// Private variables
	curve      EllipticCurve
	pw         []byte
	vpwᵤ, vpwᵥ *big.Int
	upwᵤ, upwᵥ *big.Int
	α          []byte
	αᵤ, αᵥ     *big.Int
	zᵤ, zᵥ     *big.Int
	k          []byte

	isVerified bool
	timeToHash time.Duration
}

// InitCurve will take the secret weak passphrase (pw) to initialize
// the points on the elliptic curve. The role is set to either
// 0 for the sender or 1 for the recipient.
// The curve can be siec,  p521, p256, p384
func InitCurve(pw []byte, role int, curve string, timeToHash ...time.Duration) (p *Pake, err error) {
	var ellipticCurve EllipticCurve
	switch curve {
	case "siec":
		ellipticCurve = siec.SIEC255()
	case "p521":
		ellipticCurve = elliptic.P521()
	case "p256":
		ellipticCurve = elliptic.P256()
	case "p384":
		ellipticCurve = elliptic.P384()
	default:
		err = errors.New("no such curve")
		return
	}
	if len(timeToHash) > 0 {
		return Init(pw, role, ellipticCurve, timeToHash[0])
	} else {
		return Init(pw, role, ellipticCurve)
	}
}

// Init will take the secret weak passphrase (pw) to initialize
// the points on the elliptic curve. The role is set to either
// 0 for the sender or 1 for the recipient.
// The curve can be any elliptic curve.
func Init(pw []byte, role int, curve EllipticCurve, timeToHash ...time.Duration) (p *Pake, err error) {
	p = new(Pake)
	if len(timeToHash) > 0 {
		p.timeToHash = timeToHash[0]
	} else {
		p.timeToHash = 1 * time.Second
	}
	if role == 1 {
		p.Role = 1
		p.curve = curve
		p.pw = pw
	} else {
		p.Role = 0
		p.curve = curve
		p.pw = pw
		rand1 := make([]byte, 8)
		rand2 := make([]byte, 8)
		_, err = rand.Read(rand1)
		if err != nil {
			return
		}
		_, err = rand.Read(rand2)
		if err != nil {
			return
		}
		p.Uᵤ, p.Uᵥ = p.curve.ScalarBaseMult(rand1)
		p.Vᵤ, p.Vᵥ = p.curve.ScalarBaseMult(rand2)
		if !p.curve.IsOnCurve(p.Uᵤ, p.Uᵥ) {
			err = errors.New("U values not on curve")
			return
		}
		if !p.curve.IsOnCurve(p.Vᵤ, p.Vᵥ) {
			err = errors.New("V values not on curve")
			return
		}

		// STEP: A computes X
		p.vpwᵤ, p.vpwᵥ = p.curve.ScalarMult(p.Vᵤ, p.Vᵥ, p.pw)
		p.upwᵤ, p.upwᵥ = p.curve.ScalarMult(p.Uᵤ, p.Uᵥ, p.pw)
		p.α = make([]byte, 8) // randomly generated secret
		_, err = rand.Read(p.α)
		if err != nil {
			return
		}
		p.αᵤ, p.αᵥ = p.curve.ScalarBaseMult(p.α)
		p.Xᵤ, p.Xᵥ = p.curve.Add(p.upwᵤ, p.upwᵥ, p.αᵤ, p.αᵥ) // "X"
		// now X should be sent to B
	}
	return
}

// Bytes just marshalls the PAKE structure so that
// private variables are hidden.
func (p *Pake) Bytes() []byte {
	b, _ := json.Marshal(p)
	return b
}

// Update will update itself with the other parties
// PAKE and automatically determine what stage
// and what to generate.
func (p *Pake) Update(qBytes []byte) (err error) {
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
		// initial step for B
		if p.Uᵤ == nil && q.Uᵤ != nil {
			// copy over public variables
			p.Uᵤ, p.Uᵥ = q.Uᵤ, q.Uᵥ
			p.Vᵤ, p.Vᵥ = q.Vᵤ, q.Vᵥ
			p.Xᵤ, p.Xᵥ = q.Xᵤ, q.Xᵥ

			// confirm that U,V are on curve
			if !p.curve.IsOnCurve(p.Uᵤ, p.Uᵥ) {
				err = errors.New("U values not on curve")
				return
			}
			if !p.curve.IsOnCurve(p.Vᵤ, p.Vᵥ) {
				err = errors.New("V values not on curve")
				return
			}

			// STEP: B computes Y
			p.vpwᵤ, p.vpwᵥ = p.curve.ScalarMult(p.Vᵤ, p.Vᵥ, p.pw)
			p.upwᵤ, p.upwᵥ = p.curve.ScalarMult(p.Uᵤ, p.Uᵥ, p.pw)
			p.α = make([]byte, 8) // randomly generated secret
			rand.Read(p.α)
			p.αᵤ, p.αᵥ = p.curve.ScalarBaseMult(p.α)
			p.Yᵤ, p.Yᵥ = p.curve.Add(p.vpwᵤ, p.vpwᵥ, p.αᵤ, p.αᵥ) // "Y"
			// STEP: B computes Z
			p.zᵤ, p.zᵥ = p.curve.Add(p.Xᵤ, p.Xᵥ, p.upwᵤ, new(big.Int).Neg(p.upwᵥ))
			p.zᵤ, p.zᵥ = p.curve.ScalarMult(p.zᵤ, p.zᵥ, p.α)
			// STEP: B computes k
			// H(pw,id_P,id_Q,X,Y,Z)
			HB := sha256.New()
			HB.Write(p.pw)
			HB.Write(p.Xᵤ.Bytes())
			HB.Write(p.Xᵥ.Bytes())
			HB.Write(p.Yᵤ.Bytes())
			HB.Write(p.Yᵥ.Bytes())
			HB.Write(p.zᵤ.Bytes())
			HB.Write(p.zᵥ.Bytes())
			// STEP: B computes k
			p.k = HB.Sum(nil)
			p.HkB, err = hashK(p.k, p.timeToHash)
		} else if p.HkA == nil && q.HkA != nil {
			p.HkA = q.HkA
			// verify
			err = checkKHash(p.HkA, p.k)
			if err == nil {
				p.isVerified = true
			}
		}
	} else {
		if p.HkB == nil && q.HkB != nil {
			p.HkB = q.HkB
			p.Yᵤ, p.Yᵥ = q.Yᵤ, q.Yᵥ

			// STEP: A computes Z
			p.zᵤ, p.zᵥ = p.curve.Add(p.Yᵤ, p.Yᵥ, p.vpwᵤ, new(big.Int).Neg(p.vpwᵥ))
			p.zᵤ, p.zᵥ = p.curve.ScalarMult(p.zᵤ, p.zᵥ, p.α)
			// STEP: A computes k
			// H(pw,id_P,id_Q,X,Y,Z)
			HA := sha256.New()
			HA.Write(p.pw)
			HA.Write(p.Xᵤ.Bytes())
			HA.Write(p.Xᵥ.Bytes())
			HA.Write(p.Yᵤ.Bytes())
			HA.Write(p.Yᵥ.Bytes())
			HA.Write(p.zᵤ.Bytes())
			HA.Write(p.zᵥ.Bytes())
			p.k = HA.Sum(nil)
			p.HkA, err = hashK(p.k, p.timeToHash)

			// STEP: A verifies that its session key matches B's
			// session key
			err = checkKHash(p.HkB, p.k)
			if err == nil {
				p.isVerified = true
			}
		}
	}
	return
}

// hashK generates a bcrypt hash of the password using work factor 12.
func hashK(k []byte, durationToWork time.Duration) (b []byte, err error) {
	for i := 1; i < 24; i++ {
		s := time.Now()
		b, err = bcrypt.GenerateFromPassword(k, i)
		if time.Since(s) > durationToWork {
			return
		}
	}
	return
}

// checkKHash securely compares a bcrypt hashed password with its possible
// plaintext equivalent.  Returns nil on success, or an error on failure.
func checkKHash(hash, k []byte) error {
	return bcrypt.CompareHashAndPassword(hash, k)
}

// IsVerified returns whether or not the k has been
// generated AND it confirmed to be the same as partner
func (p *Pake) IsVerified() bool {
	return p.isVerified
}

// SessionKey is returned, unless it is not generated
// in which is returns an error. This function does
// not check if it is verifies.
func (p *Pake) SessionKey() ([]byte, error) {
	var err error
	if p.k == nil {
		err = errors.New("session key not generated")
	}
	return p.k, err
}
