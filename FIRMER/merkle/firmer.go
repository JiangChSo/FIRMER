package merkle

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"

	"github.com/cloudflare/bn256"
)

var (
	salt = []byte{11, 12, 13, 14} //to be used in HashG1
)

// PublicKey is the BLS public key, i.e. a point on curve G2
type PublicKey struct {
	gx *bn256.G2
}

// ToBytes serializes the BLS public key to byte array.
func (pubKey *PublicKey) ToBytes() []byte {
	return pubKey.gx.Marshal()
}

// ToHex outputs a public key in hex
func (pubKey *PublicKey) ToHex() string {
	inBytes := pubKey.ToBytes()
	return hex.EncodeToString(inBytes)
}

// Private key is a scalar
type PrivateKey struct {
	PublicKey
	x *big.Int
}

// ToHex outputs a private key in hex
func (privKey *PrivateKey) ToHex() string {
	inBytes := privKey.ToBytes()
	return hex.EncodeToString(inBytes)
}

// ToBytes serializes the BLS private key to byte array.
func (privKey *PrivateKey) ToBytes() []byte {
	return privKey.x.Bytes()
}

// FromBytes deserializes the BLS private key from byte array.
func (privKey *PrivateKey) FromBytes(b []byte) error {
	privKey.x = new(big.Int).SetBytes(b)
	if privKey.x.Cmp(bn256.Order) >= 0 {
		return fmt.Errorf("BLS private key is out of range")
	}
	privKey.gx = new(bn256.G2).ScalarBaseMult(privKey.x)
	return nil
}

func (privKey *PrivateKey) GetPublicKey() *PublicKey {
	var pubKey PublicKey
	pubKey.gx = privKey.gx
	return &pubKey
}

// generateRandomBytes generates a random byte slice of specified length
func generateRandomBytes(length int) []byte {
	randomBytes := make([]byte, length)
	_, err := rand.Read(randomBytes)
	if err != nil {
		log.Fatalf("Failed to generate random bytes: %v", err)
	}
	return randomBytes
}

// GenerateRandomInZp generates a random integer r in Z*_p
func GenerateRandomInZp() (*big.Int, error) {
	r, err := rand.Int(rand.Reader, bn256.Order)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random r: %v", err)
	}
	// Ensure r is in Z*_p (r > 0)
	if r.Sign() == 0 {
		return GenerateRandomInZp()
	}
	return r, nil
}

// ComputeCommitment computes the commitment as hash(pwUStar || R_DU || d)
func ComputeCommitment(pwUStar *bn256.G1, R_DU, d []byte) []byte {
	// Serialize pwUStar
	pwUStarBytes := pwUStar.Marshal()

	// Concatenate pwUStar, R_DU, and d
	combined := append(pwUStarBytes, R_DU...)
	combined = append(combined, d...)

	// Compute the hash
	hash := sha256.Sum256(combined)
	return hash[:]
}

// XORBytes computes the XOR of two byte slices
func XORBytes(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, fmt.Errorf("byte slices must have the same length")
	}

	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] ^ b[i]
	}
	return result, nil
}

func hbar(data []byte) []byte {
	hash := sha256.New()
	hash.Write(data)
	return hash.Sum(nil)
}

func DeviceKeyGen(ID_DU []byte, pw_U []byte, k_U *big.Int) (*big.Int, *bn256.G2, *bn256.G1, *bn256.G1, error) {
	// Generate device-specific public key Q_DU
	Q_DU := bn256.HashG1(ID_DU, nil)
	Hpw_U := bn256.HashG1(pw_U, nil)
	pw_UStar := new(bn256.G1).ScalarMult(Hpw_U, k_U)
	combined := append(pw_UStar.Marshal(), pw_U...)
	if len(combined) > 32 {
		combined = combined[:32]
	}
	var privKey PrivateKey
	privKey.FromBytes(combined)

	//Compute device-specific private key S_DU
	s_U := privKey.x
	S_DU := new(bn256.G1).ScalarMult(Q_DU, s_U)

	//long-term public key
	PK_U := privKey.gx

	return s_U, PK_U, S_DU, Q_DU, nil
}
