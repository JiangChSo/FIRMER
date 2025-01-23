package merkle

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/cloudflare/bn256"
	"github.com/stretchr/testify/require"
	"math/big"
	"reflect"
	"testing"
	"time"
	"unsafe"
)

func TestRegKeyGen(t *testing.T) {
	// Generate a random number k_U in Z_q
	k_U, err := rand.Int(rand.Reader, bn256.Order) // Z_q randomness
	if err != nil {
		fmt.Println("Error generating k_U:", err)
		return
	}

	// Assume that pw_U is the user's password
	pw_U := []byte("password123")

	// Compute H(pw_U)
	H_pw_U := bn256.HashG1(pw_U, salt)
	// Compute k_U * H(pw_U)
	result := new(bn256.G1).ScalarMult(H_pw_U, k_U)

	// Convert the result of k_U * H(pw_U) to a byte array
	resultBytes := result.Marshal()

	// concatenated byte array
	combined := append(resultBytes, pw_U...)
	// Print the concatenated byte array
	//fmt.Println("Combined []byte:", hex.EncodeToString(combined))

	if len(combined) > 32 {
		combined = combined[:32]
	}

	// Creates and generates a private key from a concatenated byte array
	var privKey PrivateKey
	err = privKey.FromBytes(combined)
	if err != nil {
		fmt.Println("Error generating private key:", err)
		return
	}

	// Print the private key
	fmt.Println("Generated private key:", privKey.ToHex())

	// Generate the public key from the private key
	pubKey := privKey.GetPublicKey()

	// Print the public key
	fmt.Println("Generated public key:", pubKey.ToHex())
}

func TestDeviceKeyGen(t *testing.T) {
	// Generate the device identity
	ID_DU := []byte("Device123")

	// Generate the device-specific public key Q_DU
	Q_DU := bn256.HashG1(ID_DU, salt)

	// Serialize the generated public key into a byte array
	Q_DU_Bytes := Q_DU.Marshal()

	// Print the device identity and device-specific public key
	fmt.Println("Device Identity (ID_DU):", string(ID_DU))
	fmt.Println("Device-specific Public Key (Q_DU):", hex.EncodeToString(Q_DU_Bytes))

	//Step 1

	// Set the bit string length τ and λ (in bytes, 8 bits = 1 byte)
	tau := 3     // 3 bytes = 24 bits
	lambda := 16 // 16 bytes = 128 bits
	// Generate R_DU and d
	R_DU := generateRandomBytes(tau)
	d := generateRandomBytes(lambda)

	// Print the generated random bit strings
	//fmt.Println("R_DU (in hex):", hex.EncodeToString(R_DU))
	//fmt.Println("d (in hex):", hex.EncodeToString(d))

	//Step 2

	// Simulate password pw_U as a string
	pw_U := []byte("password123")

	// Generate H(pw_U) as a point on G1
	Hpw_U := bn256.HashG1(pw_U, salt)

	// Randomly select r in Z*_p
	r, err := GenerateRandomInZp()
	if err != nil {
		fmt.Println("Error generating r:", err)
		return
	}

	// Compute pw_U* = r * H(pw_U)
	pw_UStar := new(bn256.G1).ScalarMult(Hpw_U, r)

	// Compute commitment Com = h(pw_U* || R_DU || d)
	commitment := ComputeCommitment(pw_UStar, R_DU, d)

	// Output results
	fmt.Println("pw_UStar:", hex.EncodeToString(pw_UStar.Marshal()))
	fmt.Println("Commitment:", hex.EncodeToString(commitment))

	//Step 3
	// Randomly generate R_{\mathcal{D}_\mathcal{U}} 和 d
	R_PDU := generateRandomBytes(tau)

	//Step 4
	// Compute checksum_DU = R_DU ⊕ R_PDU
	checksum_DU, err := XORBytes(R_DU, R_PDU)
	if err != nil {
		fmt.Println("Error computing checksum:", err)
		return
	}

	fmt.Println("Checksum_DU:", hex.EncodeToString(checksum_DU))

	//Step 5
	checksum_PDU, _ := XORBytes(R_DU, R_PDU)
	if !bytes.Equal(checksum_DU, checksum_PDU) {
		fmt.Println("Checksum verification failed.")
		return
	}
	fmt.Println("Checksum verification succeeded.")

	// Validate commitment
	if !bytes.Equal(commitment, ComputeCommitment(pw_UStar, R_DU, d)) {
		fmt.Println("Commitment verification failed.")
		return
	}
	fmt.Println("Commitment verification succeeded.")

	// PD_U computes sigma and sends to D_U

	k_U, err := rand.Int(rand.Reader, bn256.Order) // Z_q randomness
	sigma := new(bn256.G1).ScalarMult(pw_UStar, k_U)

	//fmt.Println("Sigma:", hex.EncodeToString(sigma.Marshal()))

	//Step 6
	// Computes r^-1
	rInv := new(big.Int).ModInverse(r, bn256.Order)
	if rInv == nil {
		fmt.Println("Error computing modular inverse")
		return
	}

	// Compute r^-1 * sigma in G1
	rInvSigma := new(bn256.G1).ScalarMult(sigma, rInv)

	// Splice rInvSigma and pw_U together
	combined := append(rInvSigma.Marshal(), pw_U...)

	// Print the concatenated byte array
	//fmt.Println("Combined []byte:", hex.EncodeToString(combined))

	if len(combined) > 32 {
		combined = combined[:32]
	}
	// Generates the private key from the concatenated byte array
	var privKey PrivateKey
	err = privKey.FromBytes(combined)
	if err != nil {
		fmt.Println("Error generating private key:", err)
		return
	}

	// Print private key
	//fmt.Println("Generated private key:", privKey.ToHex())

	//Step 7
	// Computes the device-specific private key S_{D_U} = s_U * Q_{D_U}
	s_U := privKey.x
	S_DU := new(bn256.G1).ScalarMult(Q_DU, s_U)

	//Generate device-specific private key
	fmt.Println("Successfully generate the device-specific private key (S_DU):", hex.EncodeToString(S_DU.Marshal()))
}

func TestSesKeyGen(t *testing.T) {
	// Generate user1's device-specific key pair
	ID_DU1 := []byte("device1")
	pw_U1 := []byte("password1")
	k_U1 := new(big.Int).SetInt64(12345)

	_, PkU1, SDu1, QDu1, err := DeviceKeyGen(ID_DU1, pw_U1, k_U1)
	if err != nil {
		fmt.Println("Error in first call:", err)
	} else {
		//fmt.Println("User1's device-specific key pair:")
		//fmt.Println("s_U1:", sU1)
		//fmt.Println("PK_U1:", PkU1)
		//fmt.Println("S_DU1:", SDu1)
		//fmt.Println("Q_DU1:", QDu1)
	}

	// Generate user2's device-specific key pair
	ID_DU2 := []byte("device2")
	pw_U2 := []byte("password2")
	k_U2 := new(big.Int).SetInt64(67890)

	_, PkU2, SDu2, QDu2, err2 := DeviceKeyGen(ID_DU2, pw_U2, k_U2)
	if err2 != nil {
		fmt.Println("Error in second call:", err)
	} else {
		//fmt.Println("User2's device-specific key pair:")
		//fmt.Println("s_U2:", sU2)
		//fmt.Println("PK_U2:", PkU2)
		//fmt.Println("S_DU2:", SDu2)
		//fmt.Println("Q_DU2:", QDu2)
	}

	//Step 1
	x_U1, err := rand.Int(rand.Reader, bn256.Order) // Z_q randomness
	V_U1 := new(bn256.G2).ScalarBaseMult(x_U1)
	//fmt.Println("V_U1:", V_U1)

	//Step 2
	x_U2, err := rand.Int(rand.Reader, bn256.Order) // Z_q randomness
	V_U2 := new(bn256.G2).ScalarBaseMult(x_U2)
	//fmt.Println("V_U2:", V_U2)

	// generate K_U1
	part1 := bn256.Pair(SDu1, V_U2)
	part2 := bn256.Pair(QDu2, new(bn256.G2).ScalarMult(PkU2, x_U1))

	K_U1 := new(bn256.GT).Add(part1, part2)
	//fmt.Println("K_U1", K_U1)

	//Step 3

	// Compute x_U1 * V_U2
	result1 := new(bn256.G2).ScalarMult(V_U2, x_U1)

	// Construct M
	M := append(append(append(ID_DU1, ID_DU2...), V_U1.Marshal()...), V_U2.Marshal()...)
	combined1 := append(M, K_U1.Marshal()...)
	combined1 = append(combined1, result1.Marshal()...)
	combined1 = append(combined1, byte(0)) // 0

	// Compute delta_U1
	delta_U1 := hbar(combined1)
	//fmt.Println("delta_U1", delta_U1)

	// Step 4

	// Generate K_U2
	part1prime := bn256.Pair(SDu2, V_U1)
	part2prime := bn256.Pair(QDu1, new(bn256.G2).ScalarMult(PkU1, x_U2))

	K_U2 := new(bn256.GT).Add(part1prime, part2prime)
	//fmt.Println("K_U2", K_U2)

	//Verify delta_U1

	// Compute x_U2 * V_U1
	result2 := new(bn256.G2).ScalarMult(V_U1, x_U2)

	combined2 := append(M, K_U2.Marshal()...)
	combined2 = append(combined2, result2.Marshal()...)
	combined2 = append(combined2, byte(0)) //  0

	if !bytes.Equal(delta_U1, hbar(combined2)) {
		fmt.Println("invalid delta_U1")
	} else {
		fmt.Println("valid delta_U1")
	}
	//Compute session key
	sessionkeyU2 := hbar(append(combined2, byte(2)))
	//Compute delta_U2
	delta_U2 := hbar(append(combined2, byte(1)))

	//Step 5
	//Verify delta_U2
	if !bytes.Equal(delta_U2, hbar(append(combined1, byte(1)))) {
		fmt.Println("invalid delta_U2")
	} else {
		fmt.Println("valid delta_U2")
	}
	//Compute session key
	sessionkeyU1 := hbar(append(combined1, byte(2)))

	//Verify the shared session key
	if !bytes.Equal(sessionkeyU1, sessionkeyU2) {
		fmt.Println("Sessin key negotiation fails")
	} else {
		fmt.Println("Session key is shared between U1 and U2")
	}
}

func TestKeyUpdate(t *testing.T) {
	// Generate a new random number k_U in Z_q
	k_U, err := rand.Int(rand.Reader, bn256.Order) // Z_q randomness
	if err != nil {
		fmt.Println("Error generating k_U:", err)
		return
	}

	// Assume that pw_U is the user's new password
	pw_U := []byte("passwordnew")

	// Compute H(pw_U)
	H_pw_U := bn256.HashG1(pw_U, salt)
	// Compute k_U * H(pw_U)
	result := new(bn256.G1).ScalarMult(H_pw_U, k_U)

	// Concatenate k_U * H(pw_U) and pw_U together
	resultBytes := result.Marshal()
	combined := append(resultBytes, pw_U...)
	// Print the concatenated byte array
	//fmt.Println("Combined []byte:", hex.EncodeToString(combined))
	if len(combined) > 32 {
		combined = combined[:32]
	}

	// Generate the new private key from the concatenated byte array
	var privKey PrivateKey
	err = privKey.FromBytes(combined)
	if err != nil {
		fmt.Println("Error generating private key:", err)
		return
	}

	// Print the new private key
	fmt.Println("Generated the new private key:", privKey.ToHex())

	// Generate the new public key from the new private key
	pubKey := privKey.GetPublicKey()

	// Print the new public key
	fmt.Println("Generated the new public key:", pubKey.ToHex())
}

func TestDeviceKeyGen10TimesAverageDuration(t *testing.T) {
	const runs = 10
	var totalDuration time.Duration

	for i := 0; i < runs; i++ {
		start := time.Now()

		TestDeviceKeyGen(&testing.T{})

		duration := time.Since(start)
		totalDuration += duration

	}

	averageDuration := totalDuration.Seconds() / float64(runs)
	fmt.Printf("\nAverage Duration: %v\n", averageDuration)
}

func TestRegKeyGen10TimesAverageDuration(t *testing.T) {
	const runs = 10
	var totalDuration time.Duration

	for i := 0; i < runs; i++ {
		start := time.Now()

		TestRegKeyGen(&testing.T{})

		duration := time.Since(start)
		totalDuration += duration

	}

	averageDuration := totalDuration.Seconds() / float64(runs)
	fmt.Printf("\nAverage Duration: %v\n", averageDuration)
}

func TestSesKeyGen10TimesAverageDuration(t *testing.T) {
	const runs = 10
	var totalDuration time.Duration

	for i := 0; i < runs; i++ {
		start := time.Now()

		TestSesKeyGen(&testing.T{})

		duration := time.Since(start)
		totalDuration += duration

	}

	averageDuration := totalDuration.Seconds() / float64(runs)
	fmt.Printf("\nAverage Duration: %v\n", averageDuration)
}

func TestKeyUpdate10TimesAverageDuration(t *testing.T) {
	const runs = 10
	var totalDuration time.Duration

	for i := 0; i < runs; i++ {
		start := time.Now()

		TestKeyUpdate(&testing.T{})

		duration := time.Since(start)
		totalDuration += duration

	}

	averageDuration := totalDuration.Seconds() / float64(runs)
	fmt.Printf("\nAverage Duration: %v\n", averageDuration)
}

func GenerateAddScount(n int, count *int) (kvps []KeyValuePair) {
	for i := *count; i < n+*count; i++ {
		// Use the index directly as the key, converted to a string
		key := []byte(fmt.Sprintf("usr%d", i))
		kvps = append(kvps, KeyValuePair{
			Key:   key,
			Value: fmt.Sprintf("value%d", i),
		})
	}
	*count = n + *count
	return kvps
}

// test1
// TestDirUpdate
func TestDirUpdate(t *testing.T) {

	AverageCost := func(runs, num_o int) {
		//Tree_a initialization
		ctx := NewLoggerContextTodoForTesting(t)
		pp := GenPP()
		Tree_a := Init(pp)
		require.NotNil(t, Tree_a, "Tree_a initialization failed")

		//Insert 100k key-value pairs into Tree_a
		S_Tree_a := GenerateInitS(1, 100000)
		comTree_a1, _, SeqnoTree_a1 := Update(Tree_a, S_Tree_a, ctx)

		//Tree_o initialization
		Tree_o := Init(pp)
		require.NotNil(t, Tree_o, "Tree_o initialization failed")

		//Insert 10k key-value pairs into Tree_o
		S_Tree_o := GenerateInitS(1, 10000)
		comTree_o1, _, SeqnoTree_o1 := Update(Tree_o, S_Tree_o, ctx)

		// Construct com
		com := append(comTree_a1, comTree_o1...)
		// Compute com
		com = hbar(com)

		dirUpdateHelper := func(num_o, num_a int, count_a, count_o *int) (costTime time.Duration) {
			//Insert 3 key-value pairs into Tree_o
			S_Tree_o2 := GenerateAddScount(num_o, count_o)

			//Insert 6、12、18、24、30、36 key-value pairs into Tree_a
			S_Tree_a2 := GenerateAddScount(num_a, count_a)

			starTime := time.Now()

			comTree_o2, _, SeqnoTree_o2 := Update(Tree_o, S_Tree_o2, ctx)
			comTree_a2, _, SeqnoTree_a2 := Update(Tree_a, S_Tree_a2, ctx)

			_, err_o := Tree_o.GetExtensionProof(ctx, nil, SeqnoTree_o1, SeqnoTree_o2)
			_, err_a := Tree_a.GetExtensionProof(ctx, nil, SeqnoTree_a1, SeqnoTree_a2)

			if err_o == nil && err_a == nil {
				// Construct com
				com = append(com, comTree_a2...)
				com = append(com, comTree_o2...)
				// Compute com
				com = hbar(com)
				costTime = time.Since(starTime)
			} else {
				fmt.Printf("Verification Error err_o: %v and err_a:%v ", err_o, err_a)
				return
			}

			fmt.Printf("dirUpdateHelper(%d, %d) function costs %v\n", num_o, num_a, costTime)
			return costTime
		}

		AddAverage := func(runs, num_o, num_a int, count_a, count_o *int) (costTime time.Duration) {
			//Cumulative total time
			totalCost := time.Duration(0)

			for i := 1; i <= runs; i++ {
				costTime := dirUpdateHelper(num_o, num_a, count_a, count_o)
				fmt.Printf("Run %d: cost time = %v\n", i, costTime)
				totalCost += costTime
			}

			// Calculate the averageCost time
			averageCost := totalCost / time.Duration(runs)
			fmt.Printf("Average dirUpdateHelper(%d, %d) cost time after %d runs: %v\n", num_o, num_a, runs, averageCost)
			return averageCost
		}
		count_o := 1
		count_a := 1
		AddAverage(runs, num_o, 6, &count_a, &count_o)
		AddAverage(runs, num_o, 12, &count_a, &count_o)
		AddAverage(runs, num_o, 18, &count_a, &count_o)
		AddAverage(runs, num_o, 24, &count_a, &count_o)
		AddAverage(runs, num_o, 30, &count_a, &count_o)
		AddAverage(runs, num_o, 36, &count_a, &count_o)
	}
	//Run 10 times to average the costTime
	//(1) Insert 3 key-value pairs into the Tree_o and 6, 12, 18, 24, 30, and 36 key-value pairs into the Tree_a
	AverageCost(10, 3)

	//(2) Insert 9 key-value pairs into the Tree_o and 6, 12, 18, 24, 30, and 36 key-value pairs into the Tree_a
	AverageCost(10, 9)

	//(3) Insert 15 key-value pairs into the Tree_o and 6, 12, 18, 24, 30, and 36 key-value pairs into the Tree_a
	AverageCost(10, 15)
}

// TestDirUpdatePCS
func TestDirUpdatePCS(t *testing.T) {

	dirUpdateHelper := func(num_o, num_a int) (costTime time.Duration) {
		//Tree_a initialization
		ctx := NewLoggerContextTodoForTesting(t)
		pp := GenPP()
		Tree_a := Init(pp)
		require.NotNil(t, Tree_a, "Tree_a initialization failed")

		//Insert 100k key-value pairs into Tree_a
		S_Tree_a := GenerateInitS(1, 100000)
		comTree_a1, _, SeqnoTree_a1 := Update(Tree_a, S_Tree_a, ctx)

		//Tree_o initialization
		Tree_o := Init(pp)
		require.NotNil(t, Tree_o, "Tree_o initialization failed")

		//Insert 10k key-value pairs into Tree_o
		S_Tree_o := GenerateInitS(1, 10000)
		comTree_o1, _, SeqnoTree_o1 := Update(Tree_o, S_Tree_o, ctx)

		// Construct com
		com := append(comTree_a1, comTree_o1...)
		// Compute com
		com = hbar(com)

		//Insert 3 key-value pairs into Tree_o
		S_Tree_o2 := GenerateAddS(num_o)

		//Insert 6、12、18、24、30、36 key-value pairs into Tree_a
		S_Tree_a2 := GenerateAddS(num_a)

		starTime := time.Now()

		comTree_o2, _, SeqnoTree_o2 := PCSUpdate(Tree_o, S_Tree_o2, ctx)
		comTree_a2, _, SeqnoTree_a2 := PCSUpdate(Tree_a, S_Tree_a2, ctx)

		_, _ = Tree_o.GetExtensionProof(ctx, nil, SeqnoTree_o1, SeqnoTree_o2)
		_, _ = Tree_a.GetExtensionProof(ctx, nil, SeqnoTree_a1, SeqnoTree_a2)

		// Construct com
		com = append(com, comTree_a2...)
		com = append(com, comTree_o2...)
		// Compute com
		com = hbar(com)
		costTime = time.Since(starTime)

		fmt.Printf("dirUpdateHelper(%d, %d) function costs %v\n", num_o, num_a, costTime)
		return costTime
	}

	AverageCost := func(runs, num_o, num_a int) {
		//Cumulative total time
		totalCost := time.Duration(0)
		//Number of runs
		runs = 3

		for i := 1; i <= runs; i++ {
			costTime := dirUpdateHelper(num_o, num_a)
			fmt.Printf("Run %d: cost time = %v\n", i, costTime)
			totalCost += costTime
		}

		// Calculate the averageCost time
		averageCost := totalCost / time.Duration(runs)
		fmt.Printf("Average dirUpdateHelper(%d, %d) cost time after %d runs: %v\n", num_o, num_a, runs, averageCost)
	}

	//Run  10 times to average the costTime
	//Insert 15 key-value pairs into the Tree_o and 36 key-value pairs into the Tree_a

	AverageCost(10, 15, 36)

}

// test 2
// TestAudit
func TestAudit(t *testing.T) {

	dirUpdateHelper := func(num_o, num_a, numInit_a int) (costTime time.Duration) {
		//Tree_a initialization
		ctx := NewLoggerContextTodoForTesting(t)
		pp := GenPP()
		verifier_o := MerkleProofVerifier{cfg: pp}
		verifier_a := MerkleProofVerifier{cfg: pp}

		Tree_a := Init(pp)
		require.NotNil(t, Tree_a, "Tree_a initialization failed")

		//Insert 10、100、1k、10k、100k key-value pairs into Tree_a
		S_Tree_a := GenerateInitS(1, numInit_a)
		comTree_a1, _, SeqnoTree_a1 := Update(Tree_a, S_Tree_a, ctx)

		//Tree_o initialization
		Tree_o := Init(pp)
		require.NotNil(t, Tree_o, "Tree_o initialization failed")

		//Insert 10 key-value pairs into Tree_o
		S_Tree_o := GenerateInitS(1, 10)
		comTree_o1, _, SeqnoTree_o1 := Update(Tree_o, S_Tree_o, ctx)

		// Construct com
		com := append(comTree_a1, comTree_o1...)
		// Compute com
		com = hbar(com)

		//Insert 10 key-value pairs into Tree_o
		S_Tree_o2 := GenerateAddS(num_o)

		//Insert into Tree_a 12、24、36 key-value pairs into Tree_a, Tree_a already have 10, 100, 1k, 10k, and 100k key-value pairs, respectively
		S_Tree_a2 := GenerateAddS(num_a)

		comTree_o2, _, SeqnoTree_o2 := Update(Tree_o, S_Tree_o2, ctx)
		comTree_a2, _, SeqnoTree_a2 := Update(Tree_a, S_Tree_a2, ctx)

		eProofTree_o, _ := Tree_o.GetExtensionProof(ctx, nil, SeqnoTree_o1, SeqnoTree_o2)
		eProofTree_a, _ := Tree_a.GetExtensionProof(ctx, nil, SeqnoTree_a1, SeqnoTree_a2)

		starTime := time.Now()

		for i := 1; i < 10000; i++ {

			err_o := verifier_o.VerifyExtensionProof(ctx, &eProofTree_o, SeqnoTree_o1, comTree_o1, SeqnoTree_o2, comTree_o2)
			err_a := verifier_a.VerifyExtensionProof(ctx, &eProofTree_a, SeqnoTree_a1, comTree_a1, SeqnoTree_a2, comTree_a2)

			if err_o == nil && err_a == nil {
				// Construct com
				com = append(com, comTree_a2...)
				com = append(com, comTree_o2...)
				// Compute com
				com = hbar(com)
			} else {
				fmt.Printf("Verification Error err_o: %v and err_a:%v ", err_o, err_a)
				return
			}
		}
		costTime = time.Since(starTime)

		fmt.Printf("10000 dirUpdateHelper(%d, %d, %d) function costs  %v\n", num_o, num_a, numInit_a, costTime)
		return costTime
	}

	AverageCost := func(runs, num_o, num_a, numInit_a int) {
		//Cumulative total time
		totalCost := time.Duration(0)

		for i := 1; i <= runs; i++ {
			costTime := dirUpdateHelper(num_o, num_a, numInit_a)
			fmt.Printf("Run %d: cost time*10000 = %v\n", i, costTime)
			totalCost += costTime
		}

		// Calculate the averageCost time
		averageCost := totalCost / time.Duration(runs*10000)
		fmt.Printf("Average dirUpdateHelper(%d, %d,%d) cost time after %d runs: %v\n", num_o, num_a, numInit_a, runs, averageCost)
	}

	//Run 10 times to average the costTime
	//(1) Insert 10 key-value pairs into Tree_o and 12 key-value pairs into Tree_a, Tree_a already have 10, 100, 1k, 10k, and 100k key-value pairs, respectively
	AverageCost(10, 10, 12, 10)
	AverageCost(10, 10, 12, 100)
	AverageCost(10, 10, 12, 1000)
	AverageCost(10, 10, 12, 10000)
	AverageCost(10, 10, 12, 100000)

	//(2) Insert 10 key-value pairs into Tree_o and 24 key-value pairs into Tree_a, Tree_a already have 10, 100, 1k, 10k, and 100k key-value pairs, respectively
	AverageCost(10, 10, 24, 10)
	AverageCost(10, 10, 24, 100)
	AverageCost(10, 10, 24, 1000)
	AverageCost(10, 10, 24, 10000)
	AverageCost(10, 10, 24, 100000)

	//(3) Insert 10 key-value pairs into Tree_o and 36 key-value pairs into Tree_a, Tree_a already have 10, 100, 1k, 10k, and 100k key-value pairs, respectively
	AverageCost(10, 10, 36, 10)
	AverageCost(10, 10, 36, 100)
	AverageCost(10, 10, 36, 1000)
	AverageCost(10, 10, 36, 10000)
	AverageCost(10, 10, 36, 100000)

}

// test3
// TestMonitor
// Assume that the last key update time is the current query time
func TestMonitor(t *testing.T) {

	dirUpdateHelper := func(num_o, num_a, numInit_a int) (costTime time.Duration) {
		//Tree_a initialization
		ctx := NewLoggerContextTodoForTesting(t)
		pp := GenPP()

		Tree_a := Init(pp)
		require.NotNil(t, Tree_a, "Tree_a initialization failed")

		//Insert 10、100、1k、10k、100k key-value pairs into Tree_a
		S_Tree_a := GenerateInitS(1, numInit_a)
		comTree_a1, _, _ := Update(Tree_a, S_Tree_a, ctx)

		//Tree_o initialization
		Tree_o := Init(pp)
		require.NotNil(t, Tree_o, "Tree_o initialization failed")

		//Insert 10 key-value pairs into Tree_o
		S_Tree_o := GenerateInitS(1, 10)
		comTree_o1, _, _ := Update(Tree_o, S_Tree_o, ctx)

		// Construct com
		com := append(comTree_a1, comTree_o1...)
		// Compute com
		com = hbar(com)

		//Insert 2,4,6 key-value pairs into Tree_o
		S_Tree_o2 := GenerateAddS_Alice(num_o)

		//Insert into Tree_a 3,5,7 key-value pairs into Tree_a, Tree_a already have 10, 100, 1k, 10k, and 100k key-value pairs, respectively
		S_Tree_a2 := GenerateAddS_Alice(num_a)

		comTree_o2, _, SeqnoTree_o2 := Update(Tree_o, S_Tree_o2, ctx)
		comTree_a2, _, SeqnoTree_a2 := Update(Tree_a, S_Tree_a2, ctx)

		//Comments: One test time is too short, so here test 1000 times and take the average of the total time.
		starTime := time.Now()
		for i := 1; i < 2; i++ {
			for _, keyAlice := range S_Tree_o2 {
				πAlice_o, value_o, tSeq_o := Query(Tree_o, SeqnoTree_o2, keyAlice.Key, ctx)
				result := Verify(comTree_o2, keyAlice.Key, value_o, tSeq_o, πAlice_o, ctx, pp)
				require.Equal(t, 1, result, "Verification failed")
				require.Equal(t, keyAlice.Value, value_o)
			}
			for _, keyAlice := range S_Tree_a2 {
				πAlice_a, value_a, tSeq_a := Query(Tree_a, SeqnoTree_a2, keyAlice.Key, ctx)
				result := Verify(comTree_a2, keyAlice.Key, value_a, tSeq_a, πAlice_a, ctx, pp)
				require.Equal(t, 1, result, "Verification failed")
				require.Equal(t, keyAlice.Value, value_a)
			}
			for _, keyAlice := range S_Tree_a2 {
				πAlice_a2, value_a2, tSeq_a2 := Query(Tree_a, Seqno(int(SeqnoTree_a2)-1), keyAlice.Key, ctx)
				result := Verify(comTree_a1, keyAlice.Key, value_a2, tSeq_a2, πAlice_a2, ctx, pp)
				require.Equal(t, 0, result, "Verification failed")
			}
		}

		costTime = time.Since(starTime)

		fmt.Printf("1000 dirUpdateHelper(%d, %d, %d) function costs  %v\n", num_o, num_a, numInit_a, costTime)
		return costTime
	}

	AverageCost := func(runs, num_o, num_a, numInit_a int) {
		//Cumulative total time
		totalCost := time.Duration(0)

		for i := 1; i <= runs; i++ {
			costTime := dirUpdateHelper(num_o, num_a, numInit_a)
			fmt.Printf("Run %d: cost time = %v\n", i, costTime)
			totalCost += costTime
		}

		// Calculate the averageCost time
		averageCost := totalCost / time.Duration(runs)
		fmt.Printf("Average dirUpdateHelper(%d, %d,%d) cost time after %d runs: %v\n", num_o, num_a, numInit_a, runs, averageCost)
	}

	//Run 10 times to average the costTime
	//(1) Insert 2 key-value pairs into Tree_o and 3 key-value pairs into Tree_a, Tree_a already have 10, 100, 1k and 10k key-value pairs, respectively
	AverageCost(10, 2, 3, 10)
	AverageCost(10, 2, 3, 100)
	AverageCost(10, 2, 3, 1000)
	AverageCost(10, 2, 3, 10000)
	//AverageCost(10, 2, 3, 100000)

	//(2) Insert 4 key-value pairs into Tree_o and 5 key-value pairs into Tree_a, Tree_a already have 10, 100, 1k and 10k key-value pairs, respectively
	AverageCost(10, 4, 5, 10)
	AverageCost(10, 4, 5, 100)
	AverageCost(10, 4, 5, 1000)
	AverageCost(10, 4, 5, 10000)
	//AverageCost(10, 4, 5, 100000)

	//(3) Insert 6 key-value pairs into Tree_o and 7 key-value pairs into Tree_a, Tree_a already have 10, 100, 1k and 10k key-value pairs, respectively
	AverageCost(10, 6, 7, 10)
	AverageCost(10, 6, 7, 100)
	AverageCost(10, 6, 7, 1000)
	AverageCost(10, 6, 7, 10000)
	//AverageCost(10, 6, 7, 100000)
}

func GenerateAddS_Alice(n int) (kvps []KeyValuePair) {
	for i := 1; i <= n; i++ {
		// Use the index directly as the key, converted to a string
		key := []byte(fmt.Sprintf("Alice%d", i))
		kvps = append(kvps, KeyValuePair{
			Key:   key,
			Value: fmt.Sprintf("value%d", i),
		})
	}
	return kvps
}

// test4
// TestPubKeyReq

func TestPubKeyReq(t *testing.T) {

	dirUpdateHelper := func() (costTime time.Duration) {
		//Tree_a initialization
		ctx := NewLoggerContextTodoForTesting(t)
		pp := GenPP()

		Tree_a := Init(pp)
		require.NotNil(t, Tree_a, "Tree_a initialization failed")

		//Insert 100k key-value pairs into Tree_a (including Alice1 and Alicemark0)
		S_Tree_a := GenerateInitS(1, 99998) //99998+2=100000

		keyAlice1 := KeyValuePair{
			Key:   []byte("Alice1"),
			Value: "value0",
		}
		S_Tree_a = append(S_Tree_a, keyAlice1)

		keyAlicemark0 := KeyValuePair{
			Key:   []byte("Alicemark0"),
			Value: "value0",
		}
		S_Tree_a = append(S_Tree_a, keyAlicemark0)

		comTree_a1, _, SeqnoTree_a1 := Update(Tree_a, S_Tree_a, ctx)

		//Tree_o initialization
		Tree_o := Init(pp)
		require.NotNil(t, Tree_o, "Tree_o initialization failed")

		//Insert 10k key-value pairs into Tree_o
		S_Tree_o := GenerateInitS(1, 10000) //10000
		comTree_o1, _, _ := Update(Tree_o, S_Tree_o, ctx)

		com_random := generateRandomBytes(len(comTree_a1))

		starTime := time.Now()
		//step1
		πAlice1, value, tSeq := Query(Tree_a, SeqnoTree_a1, keyAlice1.Key, ctx)
		result := Verify(comTree_a1, keyAlice1.Key, value, tSeq, πAlice1, ctx, pp)
		require.Equal(t, 1, result, "Verification failed")

		//step2
		πAlicemark0, value, tSeq := Query(Tree_a, SeqnoTree_a1, keyAlicemark0.Key, ctx)
		result = Verify(comTree_a1, keyAlicemark0.Key, value, tSeq, πAlicemark0, ctx, pp)
		require.Equal(t, 1, result, "Verification failed")

		//step3
		πAlice1o, value, tSeq := Query(Tree_o, SeqnoTree_a1, keyAlice1.Key, ctx)
		result = Verify(comTree_o1, keyAlice1.Key, value, tSeq, πAlice1o, ctx, pp)
		require.Equal(t, 0, result, "Verification failed")

		//step4
		com := append(comTree_a1, comTree_o1...)
		com = hbar(com)
		com = append(com, com_random...)
		com = hbar(com)

		costTime = time.Since(starTime)

		fmt.Printf("dirUpdateHelper function costs %v\n", costTime)
		return costTime
	}

	AverageCost := func(runs int) {
		//Cumulative total time
		totalCost := time.Duration(0)

		for i := 1; i <= runs; i++ {
			costTime := dirUpdateHelper()
			fmt.Printf("Run %d: cost time = %v\n", i, costTime)
			totalCost += costTime
		}

		// Calculate the averageCost time
		averageCost := totalCost / time.Duration(runs)
		fmt.Printf("Average dirUpdateHelper cost time after %d runs: %v\n", runs, averageCost)
	}

	//Run 10 times to average the costTime
	AverageCost(10)
}

// test5
// TestComparisonComputationCosts
func TestComparisonComputationCosts(t *testing.T) {

	AverageCost := func(runs int) {
		//Tree_a initialization
		ctx := NewLoggerContextTodoForTesting(t)
		pp := GenPP()
		Tree_a := Init(pp)
		require.NotNil(t, Tree_a, "Tree_a initialization failed")

		//Insert 10k key-value pairs into Tree_a
		S_Tree_a := GenerateInitS(1, 10000)
		comTree_a1, _, SeqnoTree_a1 := Update(Tree_a, S_Tree_a, ctx)

		comTree_o1 := generateRandomBytes(len(comTree_a1))

		dirUpdateHelper := func(num_a int, count_a *int) (costTime time.Duration, comPrevious []byte) {

			//Insert 10k key-value pairs into Tree_a
			S_Tree_a2 := GenerateAddScount(num_a, count_a)

			starTime := time.Now()

			comTree_a2, _, SeqnoTree_a2 := Update(Tree_a, S_Tree_a2, ctx)

			_, err_a := Tree_a.GetExtensionProof(ctx, nil, SeqnoTree_a1, SeqnoTree_a2)

			if err_a == nil {
				com := append(comTree_o1, comTree_a2...)
				com = hbar(com)
				com = append(comTree_a1, com...)
				com = hbar(com)
				costTime = time.Since(starTime)
				fmt.Printf("TestComparisonComputationCosts( %d) function costs %v\n", num_a, costTime)
				return costTime, com
			} else {
				fmt.Printf("Verification Error err_a:%v ", err_a)
				return
			}
		}
		//Cumulative total time
		count_a := 1
		for i := 1; i <= runs; i++ {
			costTime, comPrevious := dirUpdateHelper(10000, &count_a)
			comTree_a1 = comPrevious
			fmt.Printf("Run %d: cost time = %v\n", i, costTime)
		}
	}

	//	Run 10 times to average the costTime
	//(1) Insert   10k key-value pairs into the Tree_a
	for i := 1; i <= 10; i++ {
		AverageCost(1) //Average of the 3 runs
	}

	//(2) Insert   10k,10k,10k,10k,10k key-value pairs into the Tree_a
	for i := 1; i <= 10; i++ {
		AverageCost(5) //Average of the 3 runs
	}
}

// test6
// TestComparisonStorageCosts

// SizeOf calculates the recursive memory size of an object in bytes.
func SizeOf(tree *Tree) uintptr {
	visited := make(map[uintptr]bool)
	return calculateNodeSize(reflect.ValueOf(tree), visited)
}

func calculateNodeSize(value reflect.Value, visited map[uintptr]bool) uintptr {
	if !value.IsValid() {
		return 0
	}

	switch value.Kind() {
	case reflect.Ptr:
		ptr := value.Pointer()
		if ptr == 0 || visited[ptr] {
			return 0
		}
		visited[ptr] = true
		return unsafe.Sizeof(ptr) + calculateNodeSize(value.Elem(), visited)

	case reflect.Struct:
		size := uintptr(0)
		for i := 0; i < value.NumField(); i++ {
			size += calculateNodeSize(value.Field(i), visited)
		}
		return size

	case reflect.Slice:
		size := unsafe.Sizeof(value.Interface()) // Slice header
		for i := 0; i < value.Len(); i++ {
			size += calculateNodeSize(value.Index(i), visited)
		}
		return size

	case reflect.Map:
		size := unsafe.Sizeof(value.Interface()) // Map header
		for _, key := range value.MapKeys() {
			size += calculateNodeSize(key, visited)
			size += calculateNodeSize(value.MapIndex(key), visited)
		}
		return size

	case reflect.Interface:
		return calculateNodeSize(value.Elem(), visited)

	case reflect.String:
		return uintptr(len(value.String())) + unsafe.Sizeof("") // String header + content

	default:
		return unsafe.Sizeof(value.Interface())
	}
}

func TestComparisonStorageCosts(t *testing.T) {

	AverageCost := func(runs int) {
		//Tree_a initialization
		ctx := NewLoggerContextTodoForTesting(t)
		pp := GenPP()
		Tree_a := Init(pp)
		require.NotNil(t, Tree_a, "Tree_a initialization failed")

		// Calculate the size of the Tree instance
		sizeInBytes := SizeOf(Tree_a)
		fmt.Printf(" When Tree_a is empty, Tree size: %d bytes (%.4f MB)\n", sizeInBytes, float64(sizeInBytes)/(1024*1024))

		dirUpdateHelper := func(num_a int, count_a *int) (sizeInBytes uintptr) {

			//Insert 10k key-value pairs into Tree_a
			S_Tree_a2 := GenerateAddScount(num_a, count_a)

			fmt.Printf("%v,%v", string(S_Tree_a2[1].Key), S_Tree_a2[1].Value)
			_, _, _ = Update(Tree_a, S_Tree_a2, ctx)

			// Calculate the size of the Tree instance
			sizeInBytes = SizeOf(Tree_a)
			fmt.Printf("After Inserting 10k key-value pairs, Tree size: %d bytes (%.4f MB)\n", sizeInBytes, float64(sizeInBytes)/(1024*1024))
			return sizeInBytes
		}
		//Cumulative total time
		count_a := 1
		for i := 1; i <= runs; i++ {
			sizeInBytes := dirUpdateHelper(10000, &count_a)
			fmt.Printf("Run %d: size in bytes: %d,(%.4f MB)\n", i, sizeInBytes, float64(sizeInBytes)/(1024*1024))
		}
	}
	//run 10 times
	//(1) Insert   10k key-value pairs into the Tree_a
	for i := 1; i <= 10; i++ {
		AverageCost(1)
	}

	//(2) Insert   10k,10k,10k,10k,10k key-value pairs into the Tree_a
	for i := 1; i <= 10; i++ {
		AverageCost(5)
	}
}
