# <font style="color:rgb(31, 35, 40);">FIRMER Implementation</font>
<font style="color:rgb(31, 35, 40);">This is a sample implementation of the FIRMER construction, which is written in Go. </font>

<font style="color:rgb(31, 35, 40);">This is an academic prototype not intended for production use.</font>

<font style="color:rgb(31, 35, 40);">  
</font>

## Outline
+ FIRMER/merkle/**RZKS.go** implements the algorithms of RZKS (GenPP, Init, Update, PCSUpdate, Query, Verify, and VerifyUpd) based on open-source codes in github.com/zoom/elektra/tree/main/merkle and github.com/zoom/elektra/tree/main/vrf.
+ FIRMER/merkle/**RZKS_test.go** tests the algorithms of RZKS via functions TestGenPP, TestInit, TestUpdate, TestPCSUpdate, TestQuery, TestVerify, and TestVerifyUpd.
+ FIRMER/merkle/**firmer_test.go** implements and tests the algorithms of FIRMER via the functions TestRegKeyGen, TestDeviceKeyGen, TestSesKeyGen, TestKeyUpdate, TestDirUpdate, TestDirUpdatePCS, TestAudit, TestMonitor and TestPubKeyReq.
+ FIRMER/merkle/**firmer_test.go** also runs comparison experiments via functions TestComparisonComputationCosts and TestComparisonStorageCosts.



Note: example commands in this README must be executed from the folder containing this file.

## 
## Running experiments
Test in a **Windows** environment：



Enter the project  FIRMER directory：

```plain
cd .\FIRMER\
```



Check if there are **RZKS_test.go** and **firmer_test.go** in the merkle package：

```plain
dir .\merkle 
```



Before running, make sure the project dependencies are in place and execute:

```plain
go mod tidy
```



Run the test function in the merkle package

```plain
go test -v -run FunctionName ./merkle
```

**FunctionName** can be any test function in the merkle package.

For example:

```plain
go test -v -run TestComparisonComputationCosts ./merkle
go test -v -run TestComparisonStorageCosts ./merkle
```




