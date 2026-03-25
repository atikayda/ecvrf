// Package ecvrf implements ECVRF-SECP256K1-SHA256-TAI per RFC 9381.
package ecvrf

import (
	"crypto/sha256"
	"errors"
	"fmt"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

const (
	suiteByte     byte = 0xFE
	ProofLen           = 81
	BetaLen            = 32
	challengeLen       = 16
	scalarLen          = 32
	compressedLen      = 33
)

var (
	ErrInvalidProofLen = errors.New("ecvrf: proof must be 81 bytes")
	ErrInvalidPoint    = errors.New("ecvrf: invalid curve point")
	ErrEncodeToCurve   = errors.New("ecvrf: encode_to_curve failed after 256 iterations")
	ErrInvalidSK       = errors.New("ecvrf: invalid secret key")
	ErrScalarOverflow  = errors.New("ecvrf: scalar >= group order")
)

func compressPoint(p *secp256k1.JacobianPoint) []byte {
	pt := *p
	pt.ToAffine()
	pub := secp256k1.NewPublicKey(&pt.X, &pt.Y)
	return pub.SerializeCompressed()
}

// encodeToCurveTAI implements RFC 9381 Section 5.4.1.1 try_and_increment.
// Returns (H point in Jacobian coords, counter that succeeded).
func encodeToCurveTAI(pubKey *secp256k1.PublicKey, alpha []byte) (secp256k1.JacobianPoint, int, error) {
	pkBytes := pubKey.SerializeCompressed()

	prefix := make([]byte, 0, 2+compressedLen)
	prefix = append(prefix, suiteByte, 0x01)
	prefix = append(prefix, pkBytes...)

	for ctr := 0; ctr <= 255; ctr++ {
		hashInput := make([]byte, 0, len(prefix)+len(alpha)+2)
		hashInput = append(hashInput, prefix...)
		hashInput = append(hashInput, alpha...)
		hashInput = append(hashInput, byte(ctr), 0x00)

		hash := sha256.Sum256(hashInput)

		// Attempt to decompress with 0x02 prefix (even y-coordinate)
		compressed := make([]byte, compressedLen)
		compressed[0] = 0x02
		copy(compressed[1:], hash[:])

		point, err := secp256k1.ParsePubKey(compressed)
		if err != nil {
			continue
		}

		var result secp256k1.JacobianPoint
		point.AsJacobian(&result)
		return result, ctr, nil
	}

	return secp256k1.JacobianPoint{}, 0, ErrEncodeToCurve
}

// nonceGeneration implements RFC 9381 Section 5.4.2.1 via RFC 6979.
// Input "message" is point_to_string(H), hashed with SHA-256 per the spec.
func nonceGeneration(privKey *secp256k1.PrivateKey, h *secp256k1.JacobianPoint) secp256k1.ModNScalar {
	hCompressed := compressPoint(h)
	digest := sha256.Sum256(hCompressed)
	skBytes := privKey.Key.Bytes()
	k := secp256k1.NonceRFC6979(skBytes[:], digest[:], nil, nil, 0)
	return *k
}

// challengeGeneration implements RFC 9381 Section 5.4.3 with 5-point input (Y, H, Gamma, U, V).
func challengeGeneration(y, h, gamma, u, v *secp256k1.JacobianPoint) secp256k1.ModNScalar {
	hashInput := make([]byte, 0, 2+5*compressedLen+1)
	hashInput = append(hashInput, suiteByte, 0x02)
	hashInput = append(hashInput, compressPoint(y)...)
	hashInput = append(hashInput, compressPoint(h)...)
	hashInput = append(hashInput, compressPoint(gamma)...)
	hashInput = append(hashInput, compressPoint(u)...)
	hashInput = append(hashInput, compressPoint(v)...)
	hashInput = append(hashInput, 0x00)

	cHash := sha256.Sum256(hashInput)

	// Truncate to first 16 bytes, zero-pad to 32 bytes for ModNScalar
	var cBytes [32]byte
	copy(cBytes[16:], cHash[:challengeLen])

	var c secp256k1.ModNScalar
	c.SetBytes(&cBytes)
	return c
}

// proofToHash implements RFC 9381 Section 5.2.
// secp256k1 cofactor is 1 so cofactor multiplication is identity.
func proofToHash(gamma *secp256k1.JacobianPoint) [BetaLen]byte {
	gammaBytes := compressPoint(gamma)

	hashInput := make([]byte, 0, 2+compressedLen+1)
	hashInput = append(hashInput, suiteByte, 0x03)
	hashInput = append(hashInput, gammaBytes...)
	hashInput = append(hashInput, 0x00)

	return sha256.Sum256(hashInput)
}

func decodeProof(pi []byte) (secp256k1.JacobianPoint, secp256k1.ModNScalar, secp256k1.ModNScalar, error) {
	if len(pi) != ProofLen {
		return secp256k1.JacobianPoint{}, secp256k1.ModNScalar{}, secp256k1.ModNScalar{},
			fmt.Errorf("%w: got %d bytes", ErrInvalidProofLen, len(pi))
	}

	gammaKey, err := secp256k1.ParsePubKey(pi[:compressedLen])
	if err != nil {
		return secp256k1.JacobianPoint{}, secp256k1.ModNScalar{}, secp256k1.ModNScalar{},
			fmt.Errorf("%w: gamma: %v", ErrInvalidPoint, err)
	}
	var gamma secp256k1.JacobianPoint
	gammaKey.AsJacobian(&gamma)

	var cBytes [32]byte
	copy(cBytes[16:], pi[compressedLen:compressedLen+challengeLen])
	var c secp256k1.ModNScalar
	c.SetBytes(&cBytes)

	var sBytes [32]byte
	copy(sBytes[:], pi[compressedLen+challengeLen:])
	var s secp256k1.ModNScalar
	overflow := s.SetBytes(&sBytes)
	if overflow != 0 {
		return secp256k1.JacobianPoint{}, secp256k1.ModNScalar{}, secp256k1.ModNScalar{}, ErrScalarOverflow
	}

	return gamma, c, s, nil
}

// Prove generates an 81-byte VRF proof: Gamma(33) || c(16) || s(32).
func Prove(sk, alpha []byte) ([]byte, error) {
	if len(sk) != scalarLen {
		return nil, fmt.Errorf("%w: must be %d bytes, got %d", ErrInvalidSK, scalarLen, len(sk))
	}

	// Validate sk is in range (0, n) before PrivKeyFromBytes silently wraps.
	var skScalar secp256k1.ModNScalar
	var skArr [32]byte
	copy(skArr[:], sk)
	overflow := skScalar.SetBytes(&skArr)
	if overflow != 0 {
		return nil, fmt.Errorf("%w: value >= group order", ErrInvalidSK)
	}
	if skScalar.IsZero() {
		return nil, fmt.Errorf("%w: zero key", ErrInvalidSK)
	}

	privKey := secp256k1.PrivKeyFromBytes(sk)
	pubKey := privKey.PubKey()

	h, _, err := encodeToCurveTAI(pubKey, alpha)
	if err != nil {
		return nil, err
	}

	// Gamma = x * H
	var gamma secp256k1.JacobianPoint
	secp256k1.ScalarMultNonConst(&privKey.Key, &h, &gamma)

	k := nonceGeneration(privKey, &h)

	// U = k * G
	var u secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(&k, &u)

	// V = k * H
	var v secp256k1.JacobianPoint
	secp256k1.ScalarMultNonConst(&k, &h, &v)

	var yJac secp256k1.JacobianPoint
	pubKey.AsJacobian(&yJac)
	c := challengeGeneration(&yJac, &h, &gamma, &u, &v)

	// s = (k + c * x) mod n
	var cx, s secp256k1.ModNScalar
	cx.Mul2(&c, &privKey.Key)
	s.Add2(&k, &cx)

	gammaBytes := compressPoint(&gamma)
	cAllBytes := c.Bytes()
	sBytes := s.Bytes()

	pi := make([]byte, 0, ProofLen)
	pi = append(pi, gammaBytes...)
	pi = append(pi, cAllBytes[16:]...)
	pi = append(pi, sBytes[:]...)

	return pi, nil
}

// Verify checks a VRF proof and returns (valid, beta).
// Beta is nil when the proof is invalid.
func Verify(pk, pi, alpha []byte) (bool, []byte) {
	gamma, c, s, err := decodeProof(pi)
	if err != nil {
		return false, nil
	}

	pubKey, err := secp256k1.ParsePubKey(pk)
	if err != nil {
		return false, nil
	}

	h, _, err := encodeToCurveTAI(pubKey, alpha)
	if err != nil {
		return false, nil
	}

	var yJac secp256k1.JacobianPoint
	pubKey.AsJacobian(&yJac)

	// U = s*G - c*Y
	var sG secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(&s, &sG)

	var negC secp256k1.ModNScalar
	negC.NegateVal(&c)

	var cY secp256k1.JacobianPoint
	secp256k1.ScalarMultNonConst(&negC, &yJac, &cY)

	var u secp256k1.JacobianPoint
	secp256k1.AddNonConst(&sG, &cY, &u)

	// V = s*H - c*Gamma
	var sH secp256k1.JacobianPoint
	secp256k1.ScalarMultNonConst(&s, &h, &sH)

	var cGamma secp256k1.JacobianPoint
	secp256k1.ScalarMultNonConst(&negC, &gamma, &cGamma)

	var v secp256k1.JacobianPoint
	secp256k1.AddNonConst(&sH, &cGamma, &v)

	cPrime := challengeGeneration(&yJac, &h, &gamma, &u, &v)

	if c.Equals(&cPrime) {
		beta := proofToHash(&gamma)
		return true, beta[:]
	}

	return false, nil
}

// DerivePublicKey returns the compressed public key (33 bytes) for a secret key.
func DerivePublicKey(sk []byte) ([]byte, error) {
	if len(sk) != scalarLen {
		return nil, fmt.Errorf("%w: must be %d bytes, got %d", ErrInvalidSK, scalarLen, len(sk))
	}
	var skScalar secp256k1.ModNScalar
	var skArr [32]byte
	copy(skArr[:], sk)
	overflow := skScalar.SetBytes(&skArr)
	if overflow != 0 {
		return nil, fmt.Errorf("%w: value >= group order", ErrInvalidSK)
	}
	if skScalar.IsZero() {
		return nil, fmt.Errorf("%w: zero key", ErrInvalidSK)
	}
	privKey := secp256k1.PrivKeyFromBytes(sk)
	return privKey.PubKey().SerializeCompressed(), nil
}

// ProofToHash extracts the VRF output (beta, 32 bytes) from a proof.
func ProofToHash(pi []byte) ([]byte, error) {
	gamma, _, _, err := decodeProof(pi)
	if err != nil {
		return nil, err
	}
	beta := proofToHash(&gamma)
	return beta[:], nil
}
