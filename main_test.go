// main_test.go
package main

import (
	"fmt"
	"testing"
)

func test() {
	//	strHandler := func(str string) string {
	//		var index int = 64
	//		for ; index < len(str); index++ {
	//			if str[index] == 0 {
	//				break
	//			}
	//		}
	//		return str[64:index]
	//	}
	//	tmpStr := `0x0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000d66696c6573746f726d2d32544200000000000000000000000000000000000000`
	//	data, _ := hex.DecodeString(tmpStr[2:])
	//	fmt.Println(strHandler(string(data)))

	//	txData := new(requestData.TransactionParameters)
	//	txData.To = "0xb735a842b061e62ce41dcaba33ae2764241b6258"
	//	txData.Data = "0x80f01981"
	//	var tmpRpcClient *Chain3Go.RpcClient
	//	tmpRpcClient = Chain3Go.NewRpcClient(vnodeIp, netType)
	//	fmt.Println(tmpRpcClient.Mc().MC_call(txData, "latest"))

	//	fmt.Println(tmpRpcClient.Mc().ScsRPCMethod_GetNonce("0x24e911d31d82f3482dd36451077d6f481da5167d", "0xd58592114ebd97525856929d5c662b72d58b767b"))
	//	txData, _ := tmpRpcClient.Mc().MC_getTransactionReceipt("0xdae1aed6e15148af816812555bca939a4e7c33974ddb79c17138c388cdf6cc63")
	//	fmt.Printf("%#v\n", txData)

	//	fmt.Println(utils.Sha3Hash("scsArray()"))

	//	testSubChain()

	//	searchAddrBalance()

	//	subTransaction()

	//	searchSubChainAddrBalance()

	//	approve()

	//	buyMintToken()

	//approve
	//buyMintToken
	//redeem
	//tx

	//	jsonStr := `{"address":"d58592114ebd97525856929d5c662b72d58b767b","crypto":{"cipher":"aes-128-ctr","ciphertext":"db96d030406419a3ca0d6e6901b3b688ad4c6f34376f048c8ed56f39d1b37169","cipherparams":{"iv":"9e6aee2025bd919866da952d3df40566"},"kdf":"scrypt","kdfparams":{"dklen":32,"n":262144,"p":1,"r":8,"salt":"f22f59cac654619c29efba26fef1c1b894691b0e2e6a2bf903104dae96d824c4"},"mac":"af807312730a542925badcb3830853a43324c8b19b27cbefff7e72f150e6576f"},"id":"d4bfe897-6bcb-4f5d-9166-cc9a4b5ba488","version":3}`
	//	nonce, err := getAddressNonce("0xd58592114ebd97525856929d5c662b72d58b767b")
	//	//	nonce, err := getAddressInSubChainNonce("0x24e911d31d82f3482dd36451077d6f481da5167d", "0xd58592114ebd97525856929d5c662b72d58b767b")
	//	if err == nil {
	//		fmt.Println(currencyConversion("approve", jsonStr, "Wlr7523286", toAddress, erc20Addr, "0xd58592114ebd97525856929d5c662b72d58b767b", "", 20, nonce))
	//		fmt.Println(currencyConversion("buyMintToken", jsonStr, "Wlr7523286", toAddress, erc20Addr, "0xd58592114ebd97525856929d5c662b72d58b767b", "", 19, nonce+1))

	//		//		fmt.Println(currencyConversion("redeem", jsonStr, "Wlr7523286", "0x24e911d31d82f3482dd36451077d6f481da5167d", "0xd609C9B69EFed83F9eD00486B06198B3b3FD5208", "0xd58592114ebd97525856929d5c662b72d58b767b", "", 1, nonce))

	//		//		fmt.Println(currencyConversion("tx", jsonStr, "Wlr7523286", "0x24e911d31d82f3482dd36451077d6f481da5167d", "0xd609C9B69EFed83F9eD00486B06198B3b3FD5208", "0xd58592114ebd97525856929d5c662b72d58b767b", "0x50463586C483D205F1f15741234F6CD2833e1A59", 1, nonce))
	//	}

	//	fmt.Println(getSubChainHeight("0x24e911d31d82f3482dd36451077d6f481da5167d"))

	//	const MainABI = "[{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"shardMapping\",\"outputs\":[{\"name\":\"shardId\",\"type\":\"uint256\",\"value\":\"0\"},{\"name\":\"isInitialized\",\"type\":\"bool\",\"value\":false},{\"name\":\"nodeCount\",\"type\":\"uint256\",\"value\":\"0\"},{\"name\":\"size\",\"type\":\"uint256\",\"value\":\"0\"},{\"name\":\"availableSize\",\"type\":\"uint256\",\"value\":\"0\"},{\"name\":\"percentage\",\"type\":\"uint256\",\"value\":\"0\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"addrs\",\"type\":\"address[]\"},{\"name\":\"addr\",\"type\":\"address\"}],\"name\":\"have\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"value\":false}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"admin\",\"type\":\"address\"}],\"name\":\"removeAdmin\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"nodeList\",\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"value\":\"0x\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"fileMapping\",\"outputs\":[{\"name\":\"fileId\",\"type\":\"uint256\",\"value\":\"0\"},{\"name\":\"fileHash\",\"type\":\"string\",\"value\":\"\"},{\"name\":\"fileName\",\"type\":\"string\",\"value\":\"\"},{\"name\":\"fileSize\",\"type\":\"uint256\",\"value\":\"0\"},{\"name\":\"fileOwner\",\"type\":\"address\",\"value\":\"0x0000000000000000000000000000000000000000\"},{\"name\":\"createTime\",\"type\":\"uint256\",\"value\":\"0\"},{\"name\":\"verifiedCount\",\"type\":\"uint256\",\"value\":\"0\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"fileList\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"value\":\"0\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"newlist\",\"type\":\"address[]\"}],\"name\":\"updateNodeList\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"uint256\"},{\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"verifyGroupMapping\",\"outputs\":[{\"name\":\"scsId\",\"type\":\"address\"},{\"name\":\"verifyNodeId\",\"type\":\"address\"},{\"name\":\"blockNumber\",\"type\":\"uint256\"},{\"name\":\"shardId\",\"type\":\"uint256\"},{\"name\":\"random_1\",\"type\":\"uint256\"},{\"name\":\"random_2\",\"type\":\"uint256\"},{\"name\":\"fileHash\",\"type\":\"string\"},{\"name\":\"totalCount\",\"type\":\"uint256\"},{\"name\":\"votedCount\",\"type\":\"uint256\"},{\"name\":\"affirmCount\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"getAllShards\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256[]\",\"value\":[]}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"num\",\"type\":\"uint256\"}],\"name\":\"setBlockVerificationInterval\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"address\"}],\"name\":\"admins\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"value\":\"0\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"userAddr\",\"type\":\"address\"},{\"name\":\"pos\",\"type\":\"uint256\"}],\"name\":\"getRedeemMapping\",\"outputs\":[{\"name\":\"redeemingAddr\",\"type\":\"address[]\",\"value\":[]},{\"name\":\"redeemingAmt\",\"type\":\"uint256[]\",\"value\":[]},{\"name\":\"redeemingtime\",\"type\":\"uint256[]\",\"value\":[]}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"verifyGroupList\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"value\":\"0\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"getCurNodeList\",\"outputs\":[{\"name\":\"nodeList\",\"type\":\"address[]\",\"value\":[]}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"verifyGroupId\",\"type\":\"uint256\"},{\"name\":\"blockNumber\",\"type\":\"uint256\"},{\"name\":\"shardId\",\"type\":\"uint256\"},{\"name\":\"random_1\",\"type\":\"uint256\"},{\"name\":\"random_2\",\"type\":\"uint256\"},{\"name\":\"fileHash\",\"type\":\"string\"}],\"name\":\"voteVerifyTransaction\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"curNodeList\",\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"value\":\"0x\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"shardList\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"value\":\"0\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"flushhash\",\"type\":\"bytes32\"},{\"name\":\"tosend\",\"type\":\"address[]\"},{\"name\":\"amount\",\"type\":\"uint256[]\"}],\"name\":\"postFlush\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"admin\",\"type\":\"address\"}],\"name\":\"addAdmin\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"fileHash\",\"type\":\"string\"},{\"name\":\"fileName\",\"type\":\"string\"},{\"name\":\"fileSize\",\"type\":\"uint256\"},{\"name\":\"createTime\",\"type\":\"uint256\"}],\"name\":\"addFile\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"scsId\",\"type\":\"address\"},{\"name\":\"beneficiary\",\"type\":\"address\"},{\"name\":\"size\",\"type\":\"uint256\"}],\"name\":\"addNode\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[],\"name\":\"redeemFromLiberumChain\",\"outputs\":[],\"payable\":true,\"stateMutability\":\"payable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"blockNumber\",\"type\":\"uint256\"},{\"name\":\"shardId\",\"type\":\"uint256\"},{\"name\":\"random_1\",\"type\":\"uint256\"},{\"name\":\"random_2\",\"type\":\"uint256\"},{\"name\":\"fileHash\",\"type\":\"string\"}],\"name\":\"submitVerifyTransaction\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"shardId\",\"type\":\"uint256\"}],\"name\":\"removeShard\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"fileId\",\"type\":\"uint256\"}],\"name\":\"removeFile\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"myAddr\",\"type\":\"address\"}],\"name\":\"getMyFileHashes\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256[]\",\"value\":[]}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"shardId\",\"type\":\"uint256\"}],\"name\":\"getAllFilesByShard\",\"outputs\":[{\"name\":\"\",\"type\":\"uint256[]\",\"value\":[]}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"scsId\",\"type\":\"address\"}],\"name\":\"removeNode\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"shardId\",\"type\":\"uint256\"},{\"name\":\"size\",\"type\":\"uint256\"}],\"name\":\"addShard\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"shardId\",\"type\":\"uint256\"}],\"name\":\"getAllVerifyGroup\",\"outputs\":[{\"name\":\"verifyGroups\",\"type\":\"uint256[]\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"amount\",\"type\":\"uint256\"}],\"name\":\"setAwardAmount\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"size\",\"type\":\"uint256\"}],\"name\":\"setShardSize\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"fileId\",\"type\":\"uint256\"}],\"name\":\"getFileById\",\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"value\":\"\"},{\"name\":\"\",\"type\":\"string\",\"value\":\"\"},{\"name\":\"\",\"type\":\"uint256\",\"value\":\"0\"},{\"name\":\"\",\"type\":\"address\",\"value\":\"0x0000000000000000000000000000000000000000\"},{\"name\":\"\",\"type\":\"uint256\",\"value\":\"0\"},{\"name\":\"\",\"type\":\"uint256\",\"value\":\"0\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"address\"}],\"name\":\"nodeMapping\",\"outputs\":[{\"name\":\"scsId\",\"type\":\"address\",\"value\":\"0x0000000000000000000000000000000000000000\"},{\"name\":\"beneficiary\",\"type\":\"address\",\"value\":\"0x0000000000000000000000000000000000000000\"},{\"name\":\"size\",\"type\":\"uint256\",\"value\":\"0\"},{\"name\":\"lastVerifiedBlock\",\"type\":\"uint256\",\"value\":\"0\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"beneficiary\",\"type\":\"address\"}],\"name\":\"award\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"payable\":true,\"stateMutability\":\"payable\",\"type\":\"constructor\"}]"
	//	var fileHash string = "QmcUvD92xsatbRos5qgNubpEBEPwEvSvQpQNArCubrSLCf"
	//	var fileName string = "test"
	//	var fileSize *big.Int = big.NewInt(100 * 1024)
	//	var createTime *big.Int = big.NewInt(1547458434)
	//	//fileHash string, fileName string, fileSize *big.Int, createTime *big.Int

	//	parsed, err := abi.JSON(strings.NewReader(MainABI))
	//	if err != nil {
	//		fmt.Println(err)
	//		return
	//	}
	//	input, inErr := parsed.Pack("addFile", fileHash, fileName, fileSize, createTime)

	//	if inErr != nil {
	//		fmt.Println(inErr)
	//		return
	//	}
	//	fmt.Println(hex.EncodeToString(input))
}
