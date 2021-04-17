package pake

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBadCurve(t *testing.T) {
	_, err := InitCurve([]byte{1, 2, 3}, 0, "bad")
	assert.NotNil(t, err)
}

func TestSessionKeyString(t *testing.T) {
	for _, curve := range AvailableCurves() {
		A, err := InitCurve([]byte{1, 2, 3}, 0, curve)
		assert.Nil(t, err)
		// initialize B
		B, err := InitCurve([]byte{1, 2, 3}, 1, curve)
		assert.Nil(t, err)
		// send A's stuff to B
		B.Update(A.Bytes())
		// send B's stuff to A
		A.Update(B.Bytes())

		s1A, err := A.SessionKey()
		assert.Nil(t, err)
		s1B, err := B.SessionKey()
		assert.Nil(t, err)
		fmt.Printf("A) K=%x\n", s1A)
		fmt.Printf("B) K=%x\n", s1B)
		assert.Equal(t, s1A, s1B)

		// test using incorrect password
		// initialize A
		A, _ = InitCurve([]byte{1, 2, 3}, 0, curve)
		// initialize B
		B, _ = InitCurve([]byte{1, 2, 4}, 1, curve)
		// send A's stuff to B
		B.Update(A.Bytes())
		// send B's stuff to A
		A.Update(B.Bytes())

		s1A, err = A.SessionKey()
		assert.Nil(t, err)
		s1B, err = B.SessionKey()
		assert.Nil(t, err)
		assert.NotEqual(t, s1A, s1B)
	}
}
