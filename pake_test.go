package pake

import (
	"crypto/elliptic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/tscholl2/siec"
)

func BenchmarkPakeSIEC255(b *testing.B) {
	curve := siec.SIEC255()
	for i := 0; i < b.N; i++ {
		// initialize A
		A, _ := Init([]byte{1, 2, 3}, 0, curve, 1*time.Microsecond)
		// initialize B
		B, _ := Init([]byte{1, 2, 3}, 1, curve, 1*time.Microsecond)
		// send A's stuff to B
		B.Update(A.Bytes())
		// send B's stuff to A
		A.Update(B.Bytes())
		// send A's stuff back to B
		B.Update(A.Bytes())
	}
}

func BenchmarkPakeP521(b *testing.B) {
	curve := elliptic.P521()
	for i := 0; i < b.N; i++ {
		// initialize A
		A, _ := Init([]byte{1, 2, 3}, 0, curve, 1*time.Microsecond)
		// initialize B
		B, _ := Init([]byte{1, 2, 3}, 1, curve, 1*time.Microsecond)
		// send A's stuff to B
		B.Update(A.Bytes())
		// send B's stuff to A
		A.Update(B.Bytes())
		// send A's stuff back to B
		B.Update(A.Bytes())
	}
}

func BenchmarkPakeP224(b *testing.B) {
	curve := elliptic.P224()
	for i := 0; i < b.N; i++ {
		// initialize A
		A, _ := Init([]byte{1, 2, 3}, 0, curve, 1*time.Microsecond)
		// initialize B
		B, _ := Init([]byte{1, 2, 3}, 1, curve, 1*time.Microsecond)
		// send A's stuff to B
		B.Update(A.Bytes())
		// send B's stuff to A
		A.Update(B.Bytes())
		// send A's stuff back to B
		B.Update(A.Bytes())
	}
}

func TestError(t *testing.T) {
	A, err := InitCurve([]byte{1, 2, 3}, 0, "nosuchcurve", 1*time.Millisecond)
	assert.NotNil(t, err)
	A, err = InitCurve([]byte{1, 2, 3}, 0, "p521")
	assert.Nil(t, err)
	_, err = A.SessionKey()
	assert.NotNil(t, err)
	B, err := InitCurve([]byte{1, 2, 3}, 0, "p521")
	assert.Nil(t, err)
	assert.NotNil(t, B.Update(A.Bytes()))
	assert.False(t, A.IsVerified())
	assert.NotNil(t, B.Update([]byte("{1:1}")))
	A.SetCurve(siec.SIEC255())

}

func TestSessionKeyString(t *testing.T) {
	curves := []string{"siec", "p384", "p521", "p256"}
	for _, curve := range curves {
		A, err := InitCurve([]byte{1, 2, 3}, 0, curve, 1*time.Millisecond)
		assert.Nil(t, err)
		// initialize B
		B, err := InitCurve([]byte{1, 2, 3}, 1, curve, 1*time.Millisecond)
		assert.Nil(t, err)
		// send A's stuff to B
		B.Update(A.Bytes())
		// send B's stuff to A
		A.Update(B.Bytes())
		// send A's stuff back to B
		B.Update(A.Bytes())
		s1, err := A.SessionKey()
		assert.Nil(t, err)
		s1B, err := B.SessionKey()
		assert.Nil(t, err)
		assert.Equal(t, s1, s1B)

		// initialize A
		A, _ = InitCurve([]byte{1, 2, 3}, 0, curve, 1*time.Millisecond)
		// initialize B
		B, _ = InitCurve([]byte{1, 2, 3}, 1, curve, 1*time.Millisecond)
		// send A's stuff to B
		B.Update(A.Bytes())
		// send B's stuff to A
		A.Update(B.Bytes())
		// send A's stuff back to B
		B.Update(A.Bytes())
		s2, err := A.SessionKey()
		assert.Nil(t, err)

		assert.NotEqual(t, s1, s2)
		assert.True(t, A.IsVerified())
		assert.True(t, B.IsVerified())
	}
}
