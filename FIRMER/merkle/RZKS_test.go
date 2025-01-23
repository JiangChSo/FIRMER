package merkle

import (
	"FIRMER/logger"
	"context"
	"fmt"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func NewLoggerContextTodoForTesting(t *testing.T) logger.ContextInterface {
	return logger.NewContext(context.TODO(), logger.NewTestLogger(t))
}

func GenerateInitS(start, end int) (kvps []KeyValuePair) {
	for i := start; i <= end; i++ {
		// Use the index directly as the key, converted to a string
		key := []byte(fmt.Sprintf("%d", i))
		kvps = append(kvps, KeyValuePair{
			Key:   key,
			Value: fmt.Sprintf("value%d", i),
		})
	}
	return kvps
}

func GenerateAddS(n int) (kvps []KeyValuePair) {
	for i := 1; i <= n; i++ {
		// Use the index directly as the key, converted to a string
		key := []byte(fmt.Sprintf("usr%d", i))
		kvps = append(kvps, KeyValuePair{
			Key:   key,
			Value: fmt.Sprintf("value%d", i),
		})
	}
	return kvps
}

func GenerateAddS2(n int) (kvps []KeyValuePair) {
	for i := 1; i <= n; i++ {
		// Use the index directly as the key, converted to a string
		key := []byte(fmt.Sprintf("usr2%d", i))
		kvps = append(kvps, KeyValuePair{
			Key:   key,
			Value: fmt.Sprintf("value%d", i),
		})
	}
	return kvps
}

func TestGenPP(t *testing.T) {
	pp := GenPP()
	require.NotZero(t, pp.KeysByteLength, "Generated Config should not have zero KeysByteLength")
}

func TestInit(t *testing.T) {
	pp := GenPP()
	st := Init(pp)
	require.NotNil(t, st, "Tree initialization failed")
}

func TestUpdate(t *testing.T) {
	ctx := NewLoggerContextTodoForTesting(t)

	pp := GenPP()
	st := Init(pp)
	require.NotNil(t, st, "Tree initialization failed")

	S := GenerateInitS(1, 100000)

	com_t, st_t, Seqno_t := Update(st, S, ctx)
	require.NotNil(t, st_t, "Updated tree is nil")
	require.NotZero(t, Seqno_t, "Sequence number is zero")
	require.NotZero(t, com_t, "TransparencyDigest is empty")
}

func TestPCSUpdate(t *testing.T) {
	ctx := NewLoggerContextTodoForTesting(t)
	pp := GenPP()
	st := Init(pp)
	require.NotNil(t, st, "Tree initialization failed")

	S := GenerateInitS(1, 100000)

	com_t, st_t, Seqno_t := PCSUpdate(st, S, ctx)
	require.NotNil(t, st_t, "Updated tree is nil")
	require.NotZero(t, Seqno_t, "Sequence number is zero")
	require.NotZero(t, com_t, "TransparencyDigest is empty")
}

func TestQuery(t *testing.T) {
	ctx := NewLoggerContextTodoForTesting(t)
	pp := GenPP()
	st := Init(pp)
	require.NotNil(t, st, "Tree initialization failed")

	S1 := GenerateInitS(1, 100000)
	_, st, _ = PCSUpdate(st, S1, ctx)

	S2 := GenerateAddS(6)
	starTime := time.Now()
	_, st_t, tSeq := Update(st, S2, ctx)
	costTime := time.Since(starTime)
	fmt.Println("Updating 6 key-value pairs costs", costTime)

	starTime = time.Now()
	π, value, tSeq := Query(st_t, tSeq, S2[1].Key, ctx)
	costTime = time.Since(starTime)
	fmt.Println("Querying 1 key-value pairs costs", costTime)

	require.NotNil(t, π, "Proof is nil")
	require.NotNil(t, value, "Value is nil")
	require.NotZero(t, tSeq, "Sequence number is zero")
	require.Equal(t, S2[1].Value, value)

}

func TestVerify(t *testing.T) {
	ctx := NewLoggerContextTodoForTesting(t)
	pp := GenPP()
	st := Init(pp)
	require.NotNil(t, st, "Tree initialization failed")

	S1 := GenerateInitS(1, 1000)
	_, st, _ = PCSUpdate(st, S1, ctx)

	S2 := GenerateAddS(6)
	starTime := time.Now()
	com_t, st_t, tSeq := Update(st, S2, ctx)
	costTime := time.Since(starTime)
	fmt.Println("Updating 6 key-value pairs costs", costTime)

	starTime = time.Now()
	π, value, tSeq := Query(st_t, tSeq, S2[1].Key, ctx)
	costTime = time.Since(starTime)
	fmt.Println("Querying 1 key-value pairs costs", costTime)

	fmt.Printf("The value is: %d\n", value)
	starTime = time.Now()
	result := Verify(com_t, S2[1].Key, value, tSeq, π, ctx, pp)
	costTime = time.Since(starTime)
	fmt.Println("Verifying 1 key-value pairs costs", costTime)
	require.Equal(t, 1, result, "Verification failed")
	require.Equal(t, S2[1].Value, value)

}

func TestVerifyUpd(t *testing.T) {
	ctx := NewLoggerContextTodoForTesting(t)
	pp := GenPP()
	st := Init(pp)
	require.NotNil(t, st, "Tree initialization failed")

	S1 := GenerateInitS(1, 1000)
	_, _, _ = PCSUpdate(st, S1, ctx)

	S2 := GenerateAddS(6)
	starTime := time.Now()
	com_start, _, startSeqno := Update(st, S2, ctx)
	costTime := time.Since(starTime)
	fmt.Println("Updating 6 key-value pairs costs", costTime)

	S3 := GenerateAddS2(12)
	starTime = time.Now()
	com_end, _, endSeqno := Update(st, S3, ctx)
	costTime = time.Since(starTime)
	fmt.Println("Updating 12 key-value pairs costs", costTime)

	fmt.Printf("startSeqno is: %d\n", int(startSeqno))
	fmt.Printf("endSeqno is:%d\n ", int(endSeqno))

	starTime = time.Now()
	result := VerifyUpd(st, startSeqno, endSeqno, com_start, com_end, ctx, pp)
	costTime = time.Since(starTime)
	fmt.Println("VerifyUpding 1 key-value pairs costs", costTime)
	require.Equal(t, 1, result, "Update verification failed")

}

func TestFimmer(t *testing.T) {
	ctx := NewLoggerContextTodoForTesting(t)
	pp := GenPP()
	st := Init(pp)
	require.NotNil(t, st, "Tree initialization failed")

	//Insert 100,000 key-value pairs for the first time
	S1 := GenerateInitS(1, 1000)
	_, _, _ = PCSUpdate(st, S1, ctx)

	//The second time 6 key-value pairs are inserted
	S2 := GenerateAddS(6)

	com_start, st_t, startSeqno := Update(st, S2, ctx)

	fmt.Printf("The startSeqno is: %d\n ", int(startSeqno))

	//Expected:This verification object S2[1] is  a member
	π2, value2, tSeq2 := Query(st_t, startSeqno, S2[1].Key, ctx)

	fmt.Printf("The tSeq2 is: %d\n", int(tSeq2))
	fmt.Printf("The value2 is: %d\n", value2)

	result2 := Verify(com_start, S2[1].Key, value2, tSeq2, π2, ctx, pp)
	require.Equal(t, 1, result2, "Verification failed")
	require.Equal(t, S2[1].Value, value2)

	//Insert 12 key-value pairs for the third time
	S3 := GenerateAddS2(12)
	//Expected:This verification object  S3[1] is not a member
	π3, value3, tSeq3 := Query(st_t, startSeqno, S3[1].Key, ctx)

	fmt.Printf("The value3 is: %d\n", value3)
	fmt.Printf("The tSeq3 is: %d\n", int(tSeq3))

	result3 := Verify(com_start, S3[1].Key, value3, tSeq3, π3, ctx, pp)
	require.Equal(t, 0, result3, "Verification failed")

	//Expected:This verification object S3[1] is  a member
	com_end, _, endSeqno := Update(st, S3, ctx)
	fmt.Printf("The endSeqno is: %d\n ", int(endSeqno))

	π4, value4, tSeq4 := Query(st_t, endSeqno, S3[1].Key, ctx)
	fmt.Printf("The tSeq2 is: %d\n", int(tSeq4))
	fmt.Printf("The value2 is: %d\n", value4)

	result4 := Verify(com_end, S3[1].Key, value4, tSeq4, π4, ctx, pp)
	require.Equal(t, 1, result4, "Verification failed")
	require.Equal(t, S3[1].Value, value4)

	//Expected: Successfully verified that  com_start and com_end are authentic and reliable.

	ResultVerifyUpd := VerifyUpd(st, startSeqno, endSeqno, com_start, com_end, ctx, pp)
	require.Equal(t, 1, ResultVerifyUpd, "Update verification failed")

	//Expected: The verification failed using com_start and TransparencyDigest(S3[1].Key).
	ResultVerifyUpd2 := VerifyUpd(st, startSeqno, endSeqno, com_start, TransparencyDigest(S3[1].Key), ctx, pp)
	require.Equal(t, 0, ResultVerifyUpd2, "Update verification failed")

}
