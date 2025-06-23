package pake

import (
	"bytes"
	"fmt"
	"sync"
	"testing"
)

func Example() {
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
	kB, _ := B.SessionKey()
	fmt.Println(bytes.Equal(kA, kB))
	// Output: true
}

func TestBadCurve(t *testing.T) {
	_, err := InitCurve([]byte{1, 2, 3}, 0, "bad")
	if err == nil {
		t.Errorf("curve should not exist!")
	}
}

func TestInvalidInputs(t *testing.T) {
	tests := []struct {
		name     string
		pw       []byte
		role     int
		curve    string
		wantErr  bool
	}{
		{"nil password", nil, 0, "p256", false},
		{"empty password", []byte{}, 0, "p256", false},
		{"invalid role negative", []byte{1, 2, 3}, -1, "p256", false},
		{"invalid role large", []byte{1, 2, 3}, 999, "p256", false},
		{"empty curve", []byte{1, 2, 3}, 0, "", true},
		{"invalid curve", []byte{1, 2, 3}, 0, "invalid", true},
		{"very long password", make([]byte, 1000), 0, "p256", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := InitCurve(tt.pw, tt.role, tt.curve)
			if (err != nil) != tt.wantErr {
				t.Errorf("InitCurve() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNilPakeOperations(t *testing.T) {
	var p *Pake

	// Test HaveSessionKey on nil pake
	if p.HaveSessionKey() {
		t.Error("HaveSessionKey() should return false for nil pake")
	}

	// Test Update on nil pake
	err := p.Update([]byte("test"))
	if err == nil {
		t.Error("Update() should return error for nil pake")
	}
}

func TestNilPakeSessionKey(t *testing.T) {
	var p *Pake

	// Test SessionKey on nil pake - this currently panics due to accessing p.K
	defer func() {
		if r := recover(); r == nil {
			t.Error("SessionKey() should panic for nil pake")
		}
	}()
	p.SessionKey()
}

func TestUpdateInvalidData(t *testing.T) {
	A, err := InitCurve([]byte{1, 2, 3}, 0, "p256")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		data        []byte
		expectPanic bool
	}{
		{"empty data", []byte{}, false},
		{"invalid json", []byte("invalid json"), false},
		{"null data", []byte("null"), true},
		{"malformed json", []byte("{invalid:}"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.expectPanic {
				defer func() {
					if r := recover(); r == nil {
						t.Errorf("Update() should panic for %s", tt.name)
					}
				}()
			}
			err := A.Update(tt.data)
			if !tt.expectPanic && err == nil {
				t.Errorf("Update() should return error for %s", tt.name)
			}
		})
	}
}

func TestSameRoleUpdate(t *testing.T) {
	A1, err := InitCurve([]byte{1, 2, 3}, 0, "p256")
	if err != nil {
		t.Fatal(err)
	}
	A2, err := InitCurve([]byte{1, 2, 3}, 0, "p256")
	if err != nil {
		t.Fatal(err)
	}

	err = A1.Update(A2.Bytes())
	if err == nil {
		t.Error("Update() should return error when updating with same role")
	}
}

func TestSessionKeyBeforeUpdate(t *testing.T) {
	A, err := InitCurve([]byte{1, 2, 3}, 0, "p256")
	if err != nil {
		t.Fatal(err)
	}

	_, err = A.SessionKey()
	if err == nil {
		t.Error("SessionKey() should return error before Update()")
	}

	if A.HaveSessionKey() {
		t.Error("HaveSessionKey() should return false before Update()")
	}
}

func TestMarshalingEdgeCases(t *testing.T) {
	// Test normal marshaling works
	A, err := InitCurve([]byte{1, 2, 3}, 0, "p256")
	if err != nil {
		t.Fatal(err)
	}
	bytes := A.Bytes()
	if len(bytes) == 0 {
		t.Error("Bytes() should return non-empty data")
	}

	// Test marshaling uninitialized pake
	var uninit *Pake
	defer func() {
		if r := recover(); r == nil {
			t.Error("Bytes() should panic for uninitialized pake")
		}
	}()
	uninit.Bytes()
}

func TestConcurrentUsage(t *testing.T) {
	const numGoroutines = 10
	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*2)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(2)
		go func(id int) {
			defer wg.Done()
			pw := []byte{byte(id % 256), 2, 3}
			A, err := InitCurve(pw, 0, "p256")
			if err != nil {
				errors <- err
				return
			}
			B, err := InitCurve(pw, 1, "p256")
			if err != nil {
				errors <- err
				return
			}

			err = B.Update(A.Bytes())
			if err != nil {
				errors <- err
				return
			}
			err = A.Update(B.Bytes())
			if err != nil {
				errors <- err
				return
			}

			kA, _ := A.SessionKey()
			kB, _ := B.SessionKey()
			if !bytes.Equal(kA, kB) {
				errors <- fmt.Errorf("keys not equal in goroutine %d", id)
			}
		}(i)

		go func(id int) {
			defer wg.Done()
			pw1 := []byte{byte(id % 256), 2, 3}
			pw2 := []byte{byte(id % 256), 2, 4}
			A, _ := InitCurve(pw1, 0, "p256")
			B, _ := InitCurve(pw2, 1, "p256")

			B.Update(A.Bytes())
			A.Update(B.Bytes())

			kA, _ := A.SessionKey()
			kB, _ := B.SessionKey()
			if bytes.Equal(kA, kB) {
				errors <- fmt.Errorf("keys should not be equal with different passwords in goroutine %d", id)
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Error(err)
	}
}

func TestAllCurvesTableDriven(t *testing.T) {
	curves := AvailableCurves()
	passwords := [][]byte{
		{1, 2, 3},
		{},
		make([]byte, 100),
		{255, 255, 255},
	}

	for _, curve := range curves {
		for i, pw := range passwords {
			t.Run(fmt.Sprintf("%s_pw%d", curve, i), func(t *testing.T) {
				A, err := InitCurve(pw, 0, curve)
				if err != nil {
					t.Fatalf("InitCurve failed for %s: %v", curve, err)
				}
				B, err := InitCurve(pw, 1, curve)
				if err != nil {
					t.Fatalf("InitCurve failed for %s: %v", curve, err)
				}

				if err = B.Update(A.Bytes()); err != nil {
					t.Fatalf("B.Update failed for %s: %v", curve, err)
				}
				if err = A.Update(B.Bytes()); err != nil {
					t.Fatalf("A.Update failed for %s: %v", curve, err)
				}

				kA, err := A.SessionKey()
				if err != nil {
					t.Fatalf("A.SessionKey failed for %s: %v", curve, err)
				}
				kB, err := B.SessionKey()
				if err != nil {
					t.Fatalf("B.SessionKey failed for %s: %v", curve, err)
				}

				if !bytes.Equal(kA, kB) {
					t.Errorf("Session keys not equal for curve %s with password %d", curve, i)
				}
				if len(kA) != 32 {
					t.Errorf("Expected session key length 32, got %d for curve %s", len(kA), curve)
				}
			})
		}
	}
}

func BenchmarkPAKE(b *testing.B) {
	curves := []string{"p256", "p384", "p521", "siec", "ed25519"}
	pw := []byte{1, 2, 3}

	for _, curve := range curves {
		b.Run(curve, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				A, _ := InitCurve(pw, 0, curve)
				B, _ := InitCurve(pw, 1, curve)
				B.Update(A.Bytes())
				A.Update(B.Bytes())
				A.SessionKey()
				B.SessionKey()
			}
		})
	}
}

func BenchmarkInit(b *testing.B) {
	pw := []byte{1, 2, 3}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = InitCurve(pw, 0, "p256")
	}
}

func BenchmarkUpdate(b *testing.B) {
	pw := []byte{1, 2, 3}
	A, _ := InitCurve(pw, 0, "p256")
	B, _ := InitCurve(pw, 1, "p256")
	aBytes := A.Bytes()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		B, _ = InitCurve(pw, 1, "p256")
		_ = B.Update(aBytes)
	}
}

func BenchmarkSessionKey(b *testing.B) {
	pw := []byte{1, 2, 3}
	A, _ := InitCurve(pw, 0, "p256")
	B, _ := InitCurve(pw, 1, "p256")
	B.Update(A.Bytes())
	A.Update(B.Bytes())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = A.SessionKey()
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
