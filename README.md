# FIRMER Implementation
This is a sample implementation of the FIRMER construction, which is written in Go. This is an academic prototype not intended for production use.

## Outline

1. **RZKS.go** implements RZKS (rotatable zero knowledge set) using the packages github.com/zoom/elektra/tree/main/merkle and github.com/zoom/elektra/tree/main/vrf
2. **RZKS_test.go** tests the algorithms in RZKS, including GenPP, Init, Update, PCSUpdate, VerifyUpd, Query, and Verify.
3. **firmer_test.go** tests the algorithms in the FIRMER construction, which is implemented based on RZKS.go and package bn256. The algorithms include RegKeyGen, DirUpdate, DirUpdatePCS, Audit, Monitor, DeviceKeyGen, PubKeyReq, SesKeyGen, and KeyUpdate.
4. **firmer_test.go** also includes comparison experiments, such as TestComparisonComputationCosts and TestComparisonStorageCosts.

---

## Running Experiments
1. Download required packages such as github.com/cloudflare/bn256.
2. Run each testing function in firmer_test.go, such as TestDirUpdate, TestAudit, and TestMonitor. 
