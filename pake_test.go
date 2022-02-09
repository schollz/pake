package pake

import (
	"bytes"
	"fmt"
	"testing"
)

func ExampleUsage() {
	// both parties should have a weak key
	weakKey := []byte{1, 2, 3}

	// initialize A
	A, err := InitCurve(weakKey, 0, "siec")
	if err != nil {
		panic(err)
	}
	// initialize B
	B, err := InitCurve(weakKey, 1, "siec")
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

	// both P and Q now have session key
	kA, _ := A.SessionKey()
	kB, _ := A.SessionKey()
	fmt.Println(bytes.Equal(kA, kB))
	// Output: true
}

func TestBadCurve(t *testing.T) {
	_, err := InitCurve([]byte{1, 2, 3}, 0, "bad")
	if err == nil {
		t.Errorf("curve should not exist!")
	}
}

func TestSessionKeyString(t *testing.T) {
	for _, curve := range AvailableCurves() {
		fmt.Printf("testing curve '%s'\n", curve)
		A, err := InitCurve([]byte{1, 2, 3}, 0, curve)
		if err != nil {
			t.Errorf("%s", err)
		}
		// initialize B
		B, err := InitCurve([]byte{1, 2, 3}, 1, curve)
		if err != nil {
			t.Errorf("%s", err)
		}
		// send A's stuff to B
		B.Update(A.Bytes())
		// send B's stuff to A
		A.Update(B.Bytes())

		s1A, err := A.SessionKey()
		if err != nil {
			t.Errorf("%s", err)
		}
		s1B, err := B.SessionKey()
		if err != nil {
			t.Errorf("%s", err)
		}
		fmt.Printf("A) K=%x\n", s1A)
		fmt.Printf("B) K=%x\n", s1B)
		if !bytes.Equal(s1A, s1B) {
			t.Errorf("keys not equal")
		}

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
		if err != nil {
			t.Errorf("%s", err)
		}
		s1B, err = B.SessionKey()
		if err != nil {
			t.Errorf("%s", err)
		}
		if bytes.Equal(s1A, s1B) {
			t.Errorf("keys should not be equal")
		}
	}
}
