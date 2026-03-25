package ecvrf

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type vectorFile struct {
	Suite           string           `json:"suite"`
	Spec            string           `json:"spec"`
	Vectors         []positiveVector `json:"vectors"`
	NegativeVectors []negativeVector `json:"negative_vectors"`
}

type positiveVector struct {
	Label string `json:"label"`
	SK    string `json:"sk"`
	PK    string `json:"pk"`
	Alpha string `json:"alpha"`
	Pi    string `json:"pi"`
	Beta  string `json:"beta"`
}

type negativeVector struct {
	Description    string `json:"description"`
	PK             string `json:"pk"`
	Alpha          string `json:"alpha"`
	Pi             string `json:"pi"`
	ExpectedVerify bool   `json:"expected_verify"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	data, err := os.ReadFile("../vectors/vectors.json")
	if err != nil {
		t.Fatalf("failed to read vectors.json: %v", err)
	}
	var vf vectorFile
	if err := json.Unmarshal(data, &vf); err != nil {
		t.Fatalf("failed to parse vectors.json: %v", err)
	}
	return vf
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("invalid hex %q: %v", s, err)
	}
	return b
}

func TestProve(t *testing.T) {
	vf := loadVectors(t)
	for _, vec := range vf.Vectors {
		t.Run(vec.Label, func(t *testing.T) {
			sk := mustHex(t, vec.SK)
			alpha := mustHex(t, vec.Alpha)

			pi, err := Prove(sk, alpha)
			if err != nil {
				t.Fatalf("Prove: %v", err)
			}

			got := hex.EncodeToString(pi)
			if got != vec.Pi {
				t.Errorf("pi mismatch\n  got:  %s\n  want: %s", got, vec.Pi)
			}
		})
	}
}

func TestVerify(t *testing.T) {
	vf := loadVectors(t)
	for _, vec := range vf.Vectors {
		t.Run(vec.Label, func(t *testing.T) {
			pk := mustHex(t, vec.PK)
			alpha := mustHex(t, vec.Alpha)
			pi := mustHex(t, vec.Pi)

			valid, beta := Verify(pk, pi, alpha)
			if !valid {
				t.Fatal("Verify returned invalid for valid proof")
			}

			got := hex.EncodeToString(beta)
			if got != vec.Beta {
				t.Errorf("beta mismatch\n  got:  %s\n  want: %s", got, vec.Beta)
			}
		})
	}
}

func TestProofToHash(t *testing.T) {
	vf := loadVectors(t)
	for _, vec := range vf.Vectors {
		t.Run(vec.Label, func(t *testing.T) {
			pi := mustHex(t, vec.Pi)

			beta, err := ProofToHash(pi)
			if err != nil {
				t.Fatalf("ProofToHash: %v", err)
			}

			got := hex.EncodeToString(beta)
			if got != vec.Beta {
				t.Errorf("beta mismatch\n  got:  %s\n  want: %s", got, vec.Beta)
			}
		})
	}
}

func TestNegativeVerify(t *testing.T) {
	vf := loadVectors(t)
	for _, vec := range vf.NegativeVectors {
		t.Run(vec.Description, func(t *testing.T) {
			pk := mustHex(t, vec.PK)
			alpha := mustHex(t, vec.Alpha)
			pi := mustHex(t, vec.Pi)

			valid, _ := Verify(pk, pi, alpha)
			if valid != vec.ExpectedVerify {
				t.Errorf("expected verify=%v, got %v", vec.ExpectedVerify, valid)
			}
		})
	}
}

func TestDerivePublicKey(t *testing.T) {
	vf := loadVectors(t)
	for _, vec := range vf.Vectors {
		t.Run(vec.Label, func(t *testing.T) {
			sk := mustHex(t, vec.SK)
			pk, err := DerivePublicKey(sk)
			if err != nil {
				t.Fatalf("DerivePublicKey: %v", err)
			}
			got := hex.EncodeToString(pk)
			if got != vec.PK {
				t.Errorf("pk mismatch\n  got:  %s\n  want: %s", got, vec.PK)
			}
		})
	}
}

func TestProveRejectsInvalidSK(t *testing.T) {
	// secp256k1 group order n
	groupOrder, _ := hex.DecodeString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")

	tests := []struct {
		name string
		sk   []byte
	}{
		{"zero key", make([]byte, 32)},
		{"sk = n (group order)", groupOrder},
		{"sk = n+1", func() []byte {
			n1 := make([]byte, 32)
			copy(n1, groupOrder)
			n1[31]++
			return n1
		}()},
		{"too short", make([]byte, 31)},
		{"too long", make([]byte, 33)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Prove(tc.sk, []byte("test"))
			if err == nil {
				t.Error("expected error for invalid sk, got nil")
			}
		})
	}
}

func TestProveDeterminism(t *testing.T) {
	vf := loadVectors(t)
	if len(vf.Vectors) == 0 {
		t.Skip("no vectors")
	}

	vec := vf.Vectors[0]
	sk := mustHex(t, vec.SK)
	alpha := mustHex(t, vec.Alpha)

	pi1, err := Prove(sk, alpha)
	if err != nil {
		t.Fatalf("Prove(1): %v", err)
	}

	pi2, err := Prove(sk, alpha)
	if err != nil {
		t.Fatalf("Prove(2): %v", err)
	}

	if hex.EncodeToString(pi1) != hex.EncodeToString(pi2) {
		t.Error("non-deterministic: two Prove calls produced different proofs")
	}
}

func TestRoundTrip(t *testing.T) {
	vf := loadVectors(t)
	for _, vec := range vf.Vectors {
		t.Run(vec.Label, func(t *testing.T) {
			sk := mustHex(t, vec.SK)
			pk := mustHex(t, vec.PK)
			alpha := mustHex(t, vec.Alpha)

			pi, err := Prove(sk, alpha)
			if err != nil {
				t.Fatalf("Prove: %v", err)
			}

			valid, beta := Verify(pk, pi, alpha)
			if !valid {
				t.Fatal("round-trip: Verify rejected own proof")
			}

			betaFromHash, err := ProofToHash(pi)
			if err != nil {
				t.Fatalf("ProofToHash: %v", err)
			}

			if hex.EncodeToString(beta) != hex.EncodeToString(betaFromHash) {
				t.Error("Verify beta != ProofToHash beta")
			}
		})
	}
}
