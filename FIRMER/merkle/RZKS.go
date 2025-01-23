package merkle

import (
	"FIRMER/logger"
	"fmt"
)

// pp:= GenPP(maxValuesPerLeaf:λ int)
func GenPP() (pp Config) {

	cfg, err := newConfigForTestWithVRF(SHA512_256Encoder{}, 1, 1)
	if err != nil {
		fmt.Println("Error when using GenPP() to generate pp:", err)
		return Config{}
	}

	fmt.Println("GenPP Function executed successfully!")
	return cfg
}

//st:=Init(maxValuesPerLeaf:pp Config)

func Init(pp Config) (st *Tree) {

	cfg := pp
	if cfg.KeysByteLength == 0 {
		fmt.Println("cfg is invalid because KeysByteLength is 0")
	}
	defaultStep := 2

	i := NewInMemoryStorageEngine(cfg)
	tree, err := NewTree(cfg, defaultStep, i, RootVersionV1)
	if err != nil {
		fmt.Println("Error when using Init Function:", err)
		return nil
	} else {
		fmt.Println("Init Function executed successfully!")
		return tree
	}
}

// com_t,st_t,t =Update(st *Tree, S []KeyValuePair, ctx logger.ContextInterface)
func Update(st *Tree, S []KeyValuePair, ctx logger.ContextInterface) (com_t TransparencyDigest, st_t *Tree, t Seqno) {

	t, root1, err := st.Build(ctx, nil, S, nil, false)
	if err != nil {
		fmt.Println("Error when using Update Function:", err)
		return
	} else {
		return root1, st, t
	}
}

// com_t,st_t,t =PCSUpdate(st *Tree, S []KeyValuePair, ctx logger.ContextInterface)
func PCSUpdate(st *Tree, S []KeyValuePair, ctx logger.ContextInterface) (com_t TransparencyDigest, st_t *Tree, t Seqno) {

	_, _, err := st.Build(ctx, nil, S, nil, false)
	t2, root2, err := st.Rotate(ctx, nil, nil)

	if err != nil {
		fmt.Println("Error when using PCSUpdate Function:", err)
		return
	} else {
		return root2, st, t2
	}
}

// (π MerkleInclusionProof, value interface{},t Seqno)=Query(st *Tree, u Seqno, label Key, ctx logger.ContextInterface,pp Config,com_t TransparencyDigest)
func Query(st *Tree, u Seqno, label Key, ctx logger.ContextInterface) (π MerkleInclusionProof, value interface{}, t Seqno) {
	ok, ret, proof, err := st.QueryKey(ctx, nil, u, label)

	if err == nil {
		if ok {
			//Generate member proofs
			t = proof.AddedAtSeqno
		} else {
			//Generate non-member proofs
			ret = nil
			t = 0
		}
		return proof, ret, t
	} else {
		fmt.Println("Error when using Query Function:", err)
		return
	}
}

// int=Verify(com_t TransparencyDigest, label Key, value interface{}, t Seqno, π MerkleInclusionProof, ctx logger.ContextInterface, pp Config)
func Verify(com_t TransparencyDigest, label Key, value interface{}, t Seqno, π MerkleInclusionProof, ctx logger.ContextInterface, pp Config) int {
	verifier := MerkleProofVerifier{cfg: pp}
	kvp := KeyValuePair{Key: label, Value: value}
	if t != 0 {
		err := verifier.VerifyInclusionProof(ctx, kvp, &π, com_t)
		if err == nil {
			//fmt.Println("This verification object is indeed a member.")
			return 1
		} else {
			fmt.Println("Verification Error:", err)
			return -1
		}
	} else {
		err := verifier.VerifyExclusionProof(ctx, kvp.Key, &π, com_t)
		if err == nil {
			//fmt.Println("This verification object is indeed not a member.")
			return 0
		} else {
			fmt.Println("Verification Error:", err)
			return -1
		}
	}
}

// int=VerifyUpd(com_t TransparencyDigest, label Key, value interface{}, t Seqno, π MerkleInclusionProof, ctx logger.ContextInterface, pp Config)
func VerifyUpd(st *Tree, startSeqno Seqno, endSeqno Seqno, com_start TransparencyDigest, com_end TransparencyDigest, ctx logger.ContextInterface, pp Config) int {
	verifier := MerkleProofVerifier{cfg: pp}

	eProof, err := st.GetExtensionProof(ctx, nil, startSeqno, endSeqno)
	if err == nil {
		fmt.Println("GetExtensionProof Function executed successfully!")
		err = verifier.VerifyExtensionProof(ctx, &eProof, startSeqno, com_start, endSeqno, com_end)
		if err == nil {
			return 1
		} else {
			fmt.Println("Verification Error:", err)
			return 0
		}
	} else {
		fmt.Println("GetExtensionProof Function executed failed!")
		return 0
	}

}
