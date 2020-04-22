// serverLayer project main.go
package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"math"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"Chain3Go/accounts/abi"
	"Chain3Go/lib/common/hexutil"

	"fmt"

	"Chain3Go"
	"Chain3Go/requestData"
	//	"Chain3Go/types"
	//	"Chain3Go/utils"
)

var (
	//程序访问的getway服务器上的go程序，访问IP
	//	getwayIp string = "http://127.0.0.1:9090"
	getwayIp string = "http://47.107.99.26:9090"

	//vnode访问IP
	vnodeIp string = "http://120.79.4.45:8545"

	//网络类型
	netType int = 101

	//vnode地址(via)
	via string = "0xd02443b8d564fed4ad332cd52508b69b511df5b8"
	//	formAddress          string = "0xcEAC4CC8524a5f8afa2cCA6cbde7270F1942b2d5"
	//	formKeystore         string = `{"address":"ceac4cc8524a5f8afa2cca6cbde7270f1942b2d5","crypto":{"cipher":"aes-128-ctr","ciphertext":"c779d78951604bdeef6fe770a3335e756ca07dfa769a77b6690f13ff05b003b1","cipherparams":{"iv":"d9fecf916859e7606c090831f1aa5d28"},"kdf":"scrypt","kdfparams":{"dklen":32,"n":262144,"p":1,"r":8,"salt":"5642ba42cac6720e874a73bb54d9e6a7add3b00d6cfffcffb5f97e8e04e777e8"},"mac":"c7ebe62e2d94c18194fe4cf1e1403ae26e9ed9f241b46b279752314e0c963157"},"id":"170e5a32-353a-4b84-a6c7-fa7e8196314a","version":3}`
	//	formKeystorePassword string = "test"

	//控制子链合约地址
	toAddress string = "0x220956d4374788ea776a0849ffd284152493a12d"
	subIp     string = "http://120.79.144.64:50066/rpc"

	//ERC20合约地址
	erc20Addr = "0x075f2aDfc0Dd588b00d446260aA7C3aA2D84bb01"
)

var (
	serverNotOpenErr              = 800  //服务未开放
	serverErr                     = 1000 //服务错误
	passwordLengthInsufficientErr = 1001 //密码长度要大于等于1
	passwordKeystoreMismatchErr   = 1002 //keystore和密码不匹配
	parameterErr                  = 1003 //参数错误
)

const (
	addFile          string = "0x75a3f2d7"
	removeFile       string = "0x51e5ec18"
	addLiberumChain    string = "0xd8709d52"
	removeLiberumChain string = "0xdd2bbda4"
)

var nonceControlMap map[string]uint64 = make(map[string]uint64)

func main() {

	http.HandleFunc("/createAddress", createAddressHandle)
	http.HandleFunc("/importAddress", importAddressHandle)
	http.HandleFunc("/saveFile", saveFileHandle)
	http.HandleFunc("/readFile", readFileHandle)
	http.HandleFunc("/removeFile", removeFileHandle)
	http.HandleFunc("/addIpfs", addIpfsSubChainHandle)
	http.HandleFunc("/deleteIpfs", deleteIpfsSubChainHandle)
	http.HandleFunc("/getAllIpfsInfo", getAllIpfsInfoHandle)

	http.HandleFunc("/subChainTransaction", subChainTransactionHandle)
	http.HandleFunc("/fstToSubChainCoin", fstToSubChainCoinHandle)
	http.HandleFunc("/subChainCoinToFst", subChainCoinToFstHandle)
	http.HandleFunc("/erc20Tx", erc20TxHandle)
	http.HandleFunc("/LBRTx", LBRTxHandle)

	log.Fatal(http.ListenAndServe(":8888", nil))
}

//返回请求状态字符串
func reStr(msg string, code int, resultData map[string]interface{}) string {

	reMap := map[string]interface{}{"message": msg, "code": code, "resultData": resultData}
	bytes, _ := json.Marshal(reMap)
	return string(bytes)
}

//创建用户keystore，address
func createAddressHandle(w http.ResponseWriter, r *http.Request) {

	/*
	   password：密码
	*/
	password := r.FormValue("password")
	if len(password) <= 0 {
		io.WriteString(w, reStr("fail", passwordLengthInsufficientErr, nil))
		return
	}
	jsonStr, address, err := Chain3Go.CreateKeystoreAddress(password)
	if err != nil {
		io.WriteString(w, reStr("fail", serverErr, nil))
		return
	}
	io.WriteString(w, reStr("success", 200, map[string]interface{}{"keystore": jsonStr, "address": address}))
}

//导入地址
func importAddressHandle(w http.ResponseWriter, r *http.Request) {

	/*
		importType：导入类型（KEYSTORE_TYPE：keyStore导入，MNEMONIC_TYPE：助记词导入，PLAINTEXTPRIVATEKEY_TYPE：私钥导入）
		keyStore：keyStore字符串
		password：密码
		mnemonic：助记词
		encryption:加密方式
		plaintextPrivateKey：明文私钥
	*/

	importType := r.FormValue("importType")
	keyStore := r.FormValue("keyStore")
	password := r.FormValue("password")
	//	mnemonic := r.FormValue("mnemonic")
	//	encryption := r.FormValue("encryption")
	plaintextPrivateKey := r.FormValue("plaintextPrivateKey")

	fmt.Println(keyStore, password)

	var keyStoreStr, address string
	if importType == "KEYSTORE_TYPE" {
		//keystore
		if len(keyStore) > 0 && len(password) > 0 {
			tmpKey, err := Chain3Go.GetPrivateKey(keyStore, password)
			if err != nil {
				io.WriteString(w, reStr("fail", passwordKeystoreMismatchErr, nil))
				return
			}
			keyStoreStr = keyStore
			address = tmpKey.Address.Hex()
		} else {
			io.WriteString(w, reStr("fail", parameterErr, nil))
			return
		}
	} else if importType == "PLAINTEXTPRIVATEKEY_TYPE" {
		//私钥
		if len(plaintextPrivateKey) == 64 && len(password) > 0 {
			var tmpErr error
			keyStoreStr, address, tmpErr = Chain3Go.GetKeystoreStr(plaintextPrivateKey, password)
			if tmpErr != nil {
				io.WriteString(w, reStr("fail", passwordKeystoreMismatchErr, nil))
				return
			}
		} else {
			io.WriteString(w, reStr("fail", parameterErr, nil))
			return
		}
	} else if importType == "MNEMONIC_TYPE" {
		//助记词
		io.WriteString(w, reStr("fail", serverNotOpenErr, nil))
		return
	} else {
		io.WriteString(w, reStr("fail", serverErr, nil))
		return
	}

	io.WriteString(w, reStr("success", 200, map[string]interface{}{"keystore": keyStoreStr, "address": address}))
}

//存储文件
func saveFileHandle(w http.ResponseWriter, r *http.Request) {

	encryptFlag := r.FormValue("encrypt") //0,不加密，1加密
	fileName := r.FormValue("fileName")
	path := r.FormValue("filePath")                   //文件路径
	address := r.FormValue("address")                 //存储地址
	addressKeystore := r.FormValue("keyStore")        //存储地址keystore
	addressPassword := r.FormValue("password")        //存储地址密码
	fileRealSize := r.FormValue("fileRealSize")       //文件大小
	subchainAddress := r.FormValue("subchainAddress") //子链合约地址
	subchainSize := r.FormValue("subchainSize")       //子链存储大小
	remainSize := r.FormValue("remainSize")           //子链存储剩余大小
	percentageUse := r.FormValue("percentageUse")     //子链存储已使用百分比
	createTime := r.FormValue("createTime")           //文件存储时间戳
	fileId := r.FormValue("fileId")                   //文件ID
	sIp := r.FormValue("sip")                         //子链IP

	bodyBytes, err := sendGetRequest("/addFile?path=" + path + "&address=" + address + fileName + "&encrypt=" + encryptFlag)
	if err != nil {
		io.WriteString(w, reStr("fail", serverErr, nil))
		fmt.Println(err)
		return
	}

	var bodyMap map[string]interface{}
	if json.Unmarshal(bodyBytes, &bodyMap) != nil {
		io.WriteString(w, reStr("fail", serverErr, nil))
		return
	}

	if bodyMap["resultData"] == nil {
		io.WriteString(w, reStr("fail", serverErr, nil))
		return
	}
	//加密后的hash
	hash := (bodyMap["resultData"].(map[string]interface{}))["hash"]

	fileIdNumber, err := strconv.ParseUint(fileId, 10, 64)
	if err != nil {
		io.WriteString(w, reStr("fail", parameterErr, nil))
		return
	}
	fileRealSizeNumber, err := strconv.ParseUint(fileRealSize, 10, 64)
	if err != nil {
		io.WriteString(w, reStr("fail", parameterErr, nil))
		return
	}
	createTimeNumber, err := strconv.ParseUint(createTime, 10, 64)
	if err != nil {
		io.WriteString(w, reStr("fail", parameterErr, nil))
		return
	}
	subchainSizeNumber, err := strconv.ParseUint(subchainSize, 10, 64)
	if err != nil {
		io.WriteString(w, reStr("fail", parameterErr, nil))
		return
	}
	remainSizeNumber, err := strconv.ParseUint(remainSize, 10, 64)
	if err != nil {
		io.WriteString(w, reStr("fail", parameterErr, nil))
		return
	}
	percentageUseNumber, err := strconv.ParseUint(percentageUse, 10, 64)
	if err != nil {
		io.WriteString(w, reStr("fail", parameterErr, nil))
		return
	}

	_, err = ipfsManagementOperate(removeAddFileParameter(fileIdNumber, fileRealSizeNumber, createTimeNumber, subchainSizeNumber, remainSizeNumber, percentageUseNumber, removeFile, hash.(string), fileName, address, subchainAddress), address, addressKeystore, addressPassword, toAddress)
	if err != nil {
		io.WriteString(w, reStr("fail", serverErr, nil))
		return
	}

	//将hash写到IPFS合约里
	_, conErr := contractOperate(sIp, "write", hash.(string), address, addressKeystore, addressPassword, subchainAddress)
	if conErr != nil {
		//请求失败
		io.WriteString(w, reStr("fail", serverErr, nil))
		return
	}

	io.WriteString(w, reStr("success", 200, map[string]interface{}{"hash": hash}))
}

//读文件
func readFileHandle(w http.ResponseWriter, r *http.Request) {

	encryptFlag := r.FormValue("encrypt") //0,不加密，1加密
	fileName := r.FormValue("fileName")
	var fileType string
	var lastIndex int = len(fileName)
	for index, value := range fileName {
		if value == '.' {
			lastIndex = index + 1
		}
	}
	fileType = fileName[lastIndex:]
	fileHash := r.FormValue("hash")
	address := r.FormValue("address")
	addressKeystore := r.FormValue("keyStore") //存储地址keystore
	addressPassword := r.FormValue("password") //存储地址密码
	subchainAddress := r.FormValue("subchainAddress")
	sIp := r.FormValue("sip") //子链IP

	//先进行合约read操作
	_, conErr := contractOperate(sIp, "read", fileHash, address, addressKeystore, addressPassword, subchainAddress)
	if conErr != nil {
		//请求失败
		io.WriteString(w, reStr("fail", serverErr, nil))
		return
	}
	time.Sleep(10 * time.Second) //等待10s，出新块才能在IPFS上get到文件

	bodyBytes, err := sendGetRequest("/lookFile?fileType=" + fileType + "&fileHash=" + fileHash + "&address=" + address + "&encrypt=" + encryptFlag)
	if err != nil {
		io.WriteString(w, reStr("fail", serverErr, nil))
		return
	}

	var bodyMap map[string]interface{}
	if json.Unmarshal(bodyBytes, &bodyMap) != nil {
		io.WriteString(w, reStr("fail", serverErr, nil))
		return
	}

	if bodyMap["resultData"] == nil {
		io.WriteString(w, reStr("fail", serverErr, nil))
		return
	}

	urlPath := (bodyMap["resultData"].(map[string]interface{}))["urlPath"]

	fmt.Println(urlPath)

	io.WriteString(w, reStr("success", 200, map[string]interface{}{"fileUrl": urlPath}))
}

//删除文件
func removeFileHandle(w http.ResponseWriter, r *http.Request) {

	fileHash := r.FormValue("hash")
	address := r.FormValue("address")
	addressKeystore := r.FormValue("keyStore") //存储地址keystore
	addressPassword := r.FormValue("password") //存储地址密码
	subchainAddress := r.FormValue("subchainAddress")
	fileRealSize := r.FormValue("fileRealSize")   //文件大小
	createTime := r.FormValue("createTime")       //创建时间
	fileName := r.FormValue("fileName")           //文件大小
	subchainSize := r.FormValue("subchainSize")   //子链存储大小
	remainSize := r.FormValue("remainSize")       //子链存储剩余大小
	percentageUse := r.FormValue("percentageUse") //子链存储已使用百分比
	fileId := r.FormValue("fileId")               //文件ID
	sIp := r.FormValue("sip")                     //子链IP

	fileIdNumber, err := strconv.ParseUint(fileId, 10, 64)
	if err != nil {
		io.WriteString(w, reStr("fail", parameterErr, nil))
		return
	}
	fileRealSizeNumber, err := strconv.ParseUint(fileRealSize, 10, 64)
	if err != nil {
		io.WriteString(w, reStr("fail", parameterErr, nil))
		return
	}
	createTimeNumber, err := strconv.ParseUint(createTime, 10, 64)
	if err != nil {
		io.WriteString(w, reStr("fail", parameterErr, nil))
		return
	}
	subchainSizeNumber, err := strconv.ParseUint(subchainSize, 10, 64)
	if err != nil {
		io.WriteString(w, reStr("fail", parameterErr, nil))
		return
	}
	remainSizeNumber, err := strconv.ParseUint(remainSize, 10, 64)
	if err != nil {
		io.WriteString(w, reStr("fail", parameterErr, nil))
		return
	}
	percentageUseNumber, err := strconv.ParseUint(percentageUse, 10, 64)
	if err != nil {
		io.WriteString(w, reStr("fail", parameterErr, nil))
		return
	}

	_, err = ipfsManagementOperate(removeAddFileParameter(fileIdNumber, fileRealSizeNumber, createTimeNumber, subchainSizeNumber, remainSizeNumber, percentageUseNumber, removeFile, fileHash, fileName, address, subchainAddress), address, addressKeystore, addressPassword, toAddress)
	if err != nil {
		io.WriteString(w, reStr("fail", serverErr, nil))
		return
	}

	//合约删除操作
	_, conErr := contractOperate(sIp, "remove", fileHash, address, addressKeystore, addressPassword, subchainAddress)
	if conErr != nil {
		//请求失败
		io.WriteString(w, reStr("fail", serverErr, nil))
		return
	}

	io.WriteString(w, reStr("success", 200, nil))
}

//增加IPFS子链
func addIpfsSubChainHandle(w http.ResponseWriter, r *http.Request) {

	//合约地址
	subchainAddress := r.FormValue("subchainAddress")
	subchainSize := r.FormValue("subchainSize")
	address := r.FormValue("address")
	addressKeystore := r.FormValue("keyStore") //存储地址keystore
	addressPassword := r.FormValue("password") //存储地址密码

	_, err := ipfsManagementOperate(removeAddLiberumChainParameter(addLiberumChain, subchainAddress, subchainSize), address, addressKeystore, addressPassword, toAddress)
	if err != nil {
		io.WriteString(w, reStr("fail", serverErr, nil))
		return
	}

	io.WriteString(w, reStr("success", 200, nil))
}

//删除IPFS子链
func deleteIpfsSubChainHandle(w http.ResponseWriter, r *http.Request) {

	//合约地址
	subchainAddress := r.FormValue("subchainAddress")
	address := r.FormValue("address")
	addressKeystore := r.FormValue("keyStore") //存储地址keystore
	addressPassword := r.FormValue("password") //存储地址密码

	_, err := ipfsManagementOperate(removeAddLiberumChainParameter(removeLiberumChain, subchainAddress, ""), address, addressKeystore, addressPassword, toAddress)
	if err != nil {
		io.WriteString(w, reStr("fail", serverErr, nil))
		return
	}

	io.WriteString(w, reStr("success", 200, nil))
}

//获取所有IPFS子链信息
func getAllIpfsInfoHandle(w http.ResponseWriter, r *http.Request) {

	io.WriteString(w, reStr("success", 200, nil))
}

//子链coin交易
func subChainTransactionHandle(w http.ResponseWriter, r *http.Request) {

	formAddr := r.FormValue("formAddress")
	toAddr := r.FormValue("toAddress")
	addressKeystore := r.FormValue("keyStore")
	addressPassword := r.FormValue("password")
	amount := r.FormValue("amount")

	amountF, convErr := strconv.ParseFloat(amount, 64)
	if convErr == nil {
		nonce, err := getAddressInSubChainNonce(toAddress, formAddr)

		value, ok := nonceControlMap[toAddress+formAddr]
		if ok {
			if nonce < value {
				nonce = value
			}
		}

		if err == nil {
			hash, reErr := currencyConversion("tx", addressKeystore, addressPassword, toAddress, erc20Addr, formAddr, toAddr, amountF, nonce)
			if reErr == nil {
				nonceControlMap[toAddress+formAddr] = nonce + 1
				io.WriteString(w, reStr("success", 200, map[string]interface{}{"hash": hash}))
				return
			}
		}
	}
	io.WriteString(w, reStr("fail", serverErr, nil))
}

//FST ===> 子链COIN
func fstToSubChainCoinHandle(w http.ResponseWriter, r *http.Request) {

	formAddr := r.FormValue("formAddress")
	addressKeystore := r.FormValue("keyStore")
	addressPassword := r.FormValue("password")
	amount := r.FormValue("amount")

	//	fmt.Println(formAddr, addressKeystore, addressPassword, amount)

	amountF, convErr := strconv.ParseFloat(amount, 64)
	if convErr == nil {
		nonce, err := getAddressNonce(formAddr)

		value, ok := nonceControlMap[formAddr]
		if ok {
			if nonce < value {
				nonce = value
			}
		}

		if err == nil {
			approveHash, reErr1 := currencyConversion("approve", addressKeystore, addressPassword, toAddress, erc20Addr, formAddr, "", amountF, nonce)
			buyMintTokenHash, reErr2 := currencyConversion("buyMintToken", addressKeystore, addressPassword, toAddress, erc20Addr, formAddr, "", amountF-1, nonce+1)

			if reErr1 == nil {
				nonceControlMap[formAddr] = nonce + 1
				if reErr2 == nil {
					nonceControlMap[formAddr] = nonce + 2
					io.WriteString(w, reStr("success", 200, map[string]interface{}{"approveHash": approveHash, "hash": buyMintTokenHash}))
					return
				}
			}
		}
	}
	io.WriteString(w, reStr("fail", serverErr, nil))
}

//子链COIN ===> FST
func subChainCoinToFstHandle(w http.ResponseWriter, r *http.Request) {

	formAddr := r.FormValue("formAddress")
	addressKeystore := r.FormValue("keyStore")
	addressPassword := r.FormValue("password")
	amount := r.FormValue("amount")

	amountF, convErr := strconv.ParseFloat(amount, 64)
	if convErr == nil {
		nonce, err := getAddressInSubChainNonce(toAddress, formAddr)

		value, ok := nonceControlMap[formAddr]
		if ok {
			if nonce < value {
				nonce = value
			}
		}

		if err == nil {
			hash, reErr := currencyConversion("redeem", addressKeystore, addressPassword, toAddress, erc20Addr, formAddr, "", amountF, nonce)

			if reErr == nil {
				nonceControlMap[toAddress+formAddr] = nonce + 1
				io.WriteString(w, reStr("success", 200, map[string]interface{}{"hash": hash}))
				return
			}
		}
	}
	io.WriteString(w, reStr("fail", serverErr, nil))
}

//erc20转账
func erc20TxHandle(w http.ResponseWriter, r *http.Request) {

	formAddr := r.FormValue("formAddress")
	toAddr := r.FormValue("toAddress")
	addressKeystore := r.FormValue("keyStore")
	addressPassword := r.FormValue("password")
	amount := r.FormValue("amount")

	amountF, convErr := strconv.ParseFloat(amount, 64)
	if convErr == nil {

		var rpcClient *Chain3Go.RpcClient
		rpcClient = Chain3Go.NewRpcClient(vnodeIp, netType)

		nonce, nonceErr := rpcClient.Mc().MC_getTransactionCount(formAddr, "latest")
		if nonceErr == nil {
			var precision int = 18
			bigAmount := new(big.Int).Mul(big.NewInt(int64(amountF*1000000)), big.NewInt(int64(math.Pow10(precision-6))))
			hexStr := hex.EncodeToString(bigAmount.Bytes())

			placeholderStr := "0000000000000000000000000000000000000000000000000000000000000000"
			dataStr := "0xa9059cbb000000000000000000000000" + toAddr[2:] + placeholderStr[:(64-len(hexStr))] + hexStr
			bytes, _ := hexutil.Decode(dataStr)

			signStr, err := Chain3Go.SubChainTxSign(
				via,
				netType,
				addressKeystore,
				addressPassword,
				formAddr,
				erc20Addr,
				big.NewInt(0),
				big.NewInt(500000),
				big.NewInt(20000000000),
				0,
				bytes,
				uint64(nonce),
			)
			if err == nil {
				hash, sendErr := rpcClient.Mc().MC_sendRawTransaction(signStr)
				if sendErr == nil {
					io.WriteString(w, reStr("success", 200, map[string]interface{}{"hash": hash}))
					return
				}
			}
		}
	}
	io.WriteString(w, reStr("fail", serverErr, nil))
}

//LBR转账 - 未测试
func LBRTxHandle(w http.ResponseWriter, r *http.Request) {

	formAddr := r.FormValue("formAddress")
	toAddr := r.FormValue("toAddress")
	addressKeystore := r.FormValue("keyStore")
	addressPassword := r.FormValue("password")
	amount := r.FormValue("amount")

	amountF, convErr := strconv.ParseFloat(amount, 64)
	if convErr == nil {

		var rpcClient *Chain3Go.RpcClient
		rpcClient = Chain3Go.NewRpcClient(vnodeIp, netType)

		nonce, nonceErr := rpcClient.Mc().MC_getTransactionCount(formAddr, "latest")
		if nonceErr == nil {
			var precision int = 18
			bigAmount := new(big.Int).Mul(big.NewInt(int64(amountF*1000000)), big.NewInt(int64(math.Pow10(precision-6))))

			signStr, err := Chain3Go.SubChainTxSign(
				via,
				netType,
				addressKeystore,
				addressPassword,
				formAddr,
				toAddr,
				bigAmount,
				big.NewInt(500000),
				big.NewInt(20000000000),
				0,
				nil,
				uint64(nonce),
			)
			if err == nil {
				hash, sendErr := rpcClient.Mc().MC_sendRawTransaction(signStr)
				if sendErr == nil {
					io.WriteString(w, reStr("success", 200, map[string]interface{}{"hash": hash}))
					return
				}
			}
		}
	}
	io.WriteString(w, reStr("fail", serverErr, nil))
}

//发送get请求
func sendGetRequest(urlPath string) ([]byte, error) {

	client := &http.Client{}
	resp, err := client.Get(getwayIp + urlPath)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, bodyErr := ioutil.ReadAll(resp.Body)
	if bodyErr != nil {
		return nil, bodyErr
	}
	return body, nil
}

//合约操作
func contractOperate(sIp, operateType, hashData, formAddress, formKeystore, formKeystorePassword, to string) (string, error) {

	//	var rpcClient *Chain3Go.RpcClient
	//	rpcClient = Chain3Go.NewRpcClient(vnodeIp, netType)
	//	var placeholderStr types.ComplexString = "0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002e"
	//	txParams := new(requestData.TransactionParameters)
	//	txParams.From = from
	//	txParams.To = to
	//	var opStr types.ComplexString
	//	if operateType == "remove" {
	//		opStr = "0x80599e4b"
	//	} else if operateType == "read" {
	//		opStr = "0x616ffe83"
	//	} else if operateType == "write" {
	//		opStr = "0xebaac771"
	//	}
	//	txParams.Data = opStr + placeholderStr + types.ComplexString(hex.EncodeToString([]byte(hashData)))
	//	return rpcClient.Mc().SCS_directCall(txParams)

	var tmpRpcClient *Chain3Go.RpcClient
	tmpRpcClient = Chain3Go.NewRpcClient(sIp, netType) //子链
	//	nonce, nonErr := tmpRpcClient.Mc().SCS_getNonce(to, formAddress)
	nonce, nonErr := tmpRpcClient.Mc().ScsRPCMethod_GetNonce(to, formAddress)
	if nonErr != nil {
		return "", nonErr
	}

	var opStr string = ""
	var placeholderStr string = "0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002e"
	if operateType == "remove" {
		opStr = "0x80599e4b"
	} else if operateType == "read" {
		opStr = "0x616ffe83"
	} else if operateType == "write" {
		opStr = "0xebaac771"
	} else {
		return "", errors.New("合约方法错误")
	}
	data := opStr + placeholderStr + hex.EncodeToString([]byte(hashData))
	fmt.Println("contractOperate:", data)

	bytes, _ := hexutil.Decode(data)

	var rpcClient *Chain3Go.RpcClient
	rpcClient = Chain3Go.NewRpcClient(vnodeIp, netType)
	signStr, err := Chain3Go.SubChainTxSign(
		via,
		netType,
		formKeystore,
		formKeystorePassword,
		formAddress,
		to,
		big.NewInt(0),
		big.NewInt(0),
		big.NewInt(0),
		1,
		bytes, //[]byte(data),
		uint64(nonce),
	)
	if err == nil {
		return rpcClient.Mc().MC_sendRawTransaction(signStr)
	}
	return "", err
}

//IPFS管理子链操作
func ipfsManagementOperate(data, formAddress, formKeystore, formKeystorePassword, to string) (string, error) {

	//		txParams := new(requestData.TransactionParameters)
	//		txParams.From = from
	//		txParams.To = to
	//		txParams.Data = types.ComplexString(data)
	//		return rpcClient.Mc().SCS_directCall(txParams)

	fmt.Println("ipfsManagementOperate:", data)

	bytes, _ := hexutil.Decode(data)

	var tmpRpcClient *Chain3Go.RpcClient
	tmpRpcClient = Chain3Go.NewRpcClient(subIp, netType) //子链
	//	nonce, nonErr := tmpRpcClient.Mc().SCS_getNonce(to, formAddress)
	nonce, nonErr := tmpRpcClient.Mc().ScsRPCMethod_GetNonce(to, formAddress)
	if nonErr == nil {
		var rpcClient *Chain3Go.RpcClient
		rpcClient = Chain3Go.NewRpcClient(vnodeIp, netType) //子链
		signStr, err := Chain3Go.SubChainTxSign(
			via,
			netType,
			formKeystore,
			formKeystorePassword,
			formAddress,
			toAddress,
			big.NewInt(0),
			big.NewInt(0),
			big.NewInt(0),
			1,
			bytes, //[]byte(data),
			uint64(nonce),
		)
		if err == nil {
			return rpcClient.Mc().MC_sendRawTransaction(signStr)
		}
		return "", err
	}
	return "", nonErr
}

func searchAddrBalance() {

	var tmpRpcClient *Chain3Go.RpcClient
	tmpRpcClient = Chain3Go.NewRpcClient(vnodeIp, netType)

	txData := new(requestData.TransactionParameters)
	txData.To = erc20Addr
	txData.Data = "0x70a08231000000000000000000000000d58592114ebd97525856929d5c662b72d58b767b"
	fmt.Println(tmpRpcClient.Mc().MC_call(txData, "latest"))

	//	tmpRpcClient.Mc().MC_getBalance("0xd58592114ebd97525856929d5c662b72d58b767b", "latest")
}

func searchSubChainAddrBalance() {

	var tmpRpcClient *Chain3Go.RpcClient
	tmpRpcClient = Chain3Go.NewRpcClient(subIp, netType) //子链

	//	fmt.Println(tmpRpcClient.Mc().ScsRPCMethod_GetNonce(toAddress, "0xd58592114ebd97525856929d5c662b72d58b767b"))

	fmt.Println(tmpRpcClient.Mc().ScsRPCMethod_GetBalance(toAddress, "0xa9da7943051252a0845d561658728556238e4f15"))
	//	fmt.Println(tmpRpcClient.Mc().ScsRPCMethod_GetBalance(toAddress, "0x50463586C483D205F1f15741234F6CD2833e1A59"))
	//	fmt.Println(tmpRpcClient.Mc().ScsRPCMethod_GetBalance("0x25f3524d2cd4119527DaB2BefEa9B4ae6E88f53a", "0xd58592114ebd97525856929d5c662b72d58b767b"))
}

func subTransaction() {

	bytes, _ := hexutil.Decode("0x50463586C483D205F1f15741234F6CD2833e1A59")
	var tmpRpcClient *Chain3Go.RpcClient
	tmpRpcClient = Chain3Go.NewRpcClient("http://35.227.40.187:50068/rpc", netType) //子链
	nonce, nonErr := tmpRpcClient.Mc().ScsRPCMethod_GetNonce("0x24e911d31d82f3482dd36451077d6f481da5167d", "0xd58592114ebd97525856929d5c662b72d58b767b")
	if nonErr == nil {
		var rpcClient *Chain3Go.RpcClient
		rpcClient = Chain3Go.NewRpcClient(vnodeIp, netType) //子链
		signStr, err := Chain3Go.SubChainTxSign(
			via,
			netType,
			`{"address":"d58592114ebd97525856929d5c662b72d58b767b","crypto":{"cipher":"aes-128-ctr","ciphertext":"db96d030406419a3ca0d6e6901b3b688ad4c6f34376f048c8ed56f39d1b37169","cipherparams":{"iv":"9e6aee2025bd919866da952d3df40566"},"kdf":"scrypt","kdfparams":{"dklen":32,"n":262144,"p":1,"r":8,"salt":"f22f59cac654619c29efba26fef1c1b894691b0e2e6a2bf903104dae96d824c4"},"mac":"af807312730a542925badcb3830853a43324c8b19b27cbefff7e72f150e6576f"},"id":"d4bfe897-6bcb-4f5d-9166-cc9a4b5ba488","version":3}`,
			"Wlr7523286",
			"0xd58592114ebd97525856929d5c662b72d58b767b",
			"0x24e911d31d82f3482dd36451077d6f481da5167d",
			big.NewInt(1),
			big.NewInt(0),
			big.NewInt(0),
			2,
			bytes,
			uint64(nonce),
		)
		if err == nil {
			fmt.Println(rpcClient.Mc().MC_sendRawTransaction(signStr))
		} else {
			fmt.Println("err:", err)
		}
	} else {
		fmt.Println("nonErr:", nonErr)
	}
}

func approve() {

	bytes, _ := hexutil.Decode("0x095ea7b300000000000000000000000024e911d31d82f3482dd36451077d6f481da5167d00000000000000000000000000000000000000000000000000000000000000ff")

	var rpcClient *Chain3Go.RpcClient
	rpcClient = Chain3Go.NewRpcClient(vnodeIp, netType) //子链
	nonce, nonErr := rpcClient.Mc().MC_getTransactionCount("0xd58592114ebd97525856929d5c662b72d58b767b", "latest")

	if nonErr == nil {

		signStr, err := Chain3Go.SubChainTxSign(
			via,
			netType,
			`{"address":"d58592114ebd97525856929d5c662b72d58b767b","crypto":{"cipher":"aes-128-ctr","ciphertext":"db96d030406419a3ca0d6e6901b3b688ad4c6f34376f048c8ed56f39d1b37169","cipherparams":{"iv":"9e6aee2025bd919866da952d3df40566"},"kdf":"scrypt","kdfparams":{"dklen":32,"n":262144,"p":1,"r":8,"salt":"f22f59cac654619c29efba26fef1c1b894691b0e2e6a2bf903104dae96d824c4"},"mac":"af807312730a542925badcb3830853a43324c8b19b27cbefff7e72f150e6576f"},"id":"d4bfe897-6bcb-4f5d-9166-cc9a4b5ba488","version":3}`,
			"Wlr7523286",
			"0xd58592114ebd97525856929d5c662b72d58b767b",
			"0xd609C9B69EFed83F9eD00486B06198B3b3FD5208",
			big.NewInt(0),
			big.NewInt(50000),
			big.NewInt(20000000000),
			0,
			bytes,
			uint64(nonce),
		)
		if err == nil {
			fmt.Println(rpcClient.Mc().MC_sendRawTransaction(signStr))
		} else {
			fmt.Println("err:", err)
		}
	} else {
		fmt.Println("nonErr:", nonErr)
	}
}

func buyMintToken() {

	bytes, _ := hexutil.Decode("0xa1abbbc200000000000000000000000024e911d31d82f3482dd36451077d6f481da5167d000000000000000000000000000000000000000000000000000000000fffffff")

	var rpcClient *Chain3Go.RpcClient
	rpcClient = Chain3Go.NewRpcClient(vnodeIp, netType) //子链
	nonce, nonErr := rpcClient.Mc().MC_getTransactionCount("0xd58592114ebd97525856929d5c662b72d58b767b", "latest")

	if nonErr == nil {

		signStr, err := Chain3Go.SubChainTxSign(
			via,
			netType,
			`{"address":"d58592114ebd97525856929d5c662b72d58b767b","crypto":{"cipher":"aes-128-ctr","ciphertext":"db96d030406419a3ca0d6e6901b3b688ad4c6f34376f048c8ed56f39d1b37169","cipherparams":{"iv":"9e6aee2025bd919866da952d3df40566"},"kdf":"scrypt","kdfparams":{"dklen":32,"n":262144,"p":1,"r":8,"salt":"f22f59cac654619c29efba26fef1c1b894691b0e2e6a2bf903104dae96d824c4"},"mac":"af807312730a542925badcb3830853a43324c8b19b27cbefff7e72f150e6576f"},"id":"d4bfe897-6bcb-4f5d-9166-cc9a4b5ba488","version":3}`,
			"Wlr7523286",
			"0xd58592114ebd97525856929d5c662b72d58b767b",
			"0x24e911d31d82f3482dd36451077d6f481da5167d",
			big.NewInt(0),
			big.NewInt(500000),
			big.NewInt(20000000000),
			0,
			bytes,
			uint64(nonce),
		)
		if err == nil {
			fmt.Println(rpcClient.Mc().MC_sendRawTransaction(signStr))
		} else {
			fmt.Println("err:", err)
		}
	} else {
		fmt.Println("nonErr:", nonErr)
	}
}

//approve：充值子链coin第一步
//buyMintToken：充值子链coin第二步
//redeem：提币
//return：交易hash
func currencyConversion(funcName, keyStoreStr, password, contractAddress, erc20Address, fromAddr, toAddr string, amount float64, nonce uint64) (string, error) {

	var precision int = 18
	bigAmount := new(big.Int).Mul(big.NewInt(int64(amount*1000000)), big.NewInt(int64(math.Pow10(precision-6))))
	hexStr := hex.EncodeToString(bigAmount.Bytes())
	placeholderStr := "0000000000000000000000000000000000000000000000000000000000000000"

	var gas int64 = 9000000
	var gasPrice int64 = 20000000000

	var shardingFlag uint64 = 0

	var dataStr, to string
	if funcName == "approve" {
		//to:erc20合约地址
		dataStr = "0x095ea7b3000000000000000000000000" + contractAddress[2:] + placeholderStr[:(64-len(hexStr))] + hexStr
		to = erc20Address
		bigAmount = big.NewInt(0)
	} else if funcName == "buyMintToken" {
		//to:子链合约地址
		dataStr = "0xa1abbbc2000000000000000000000000" + contractAddress[2:] + placeholderStr[:(64-len(hexStr))] + hexStr
		to = contractAddress
		bigAmount = big.NewInt(0)
	} else if funcName == "redeem" {
		//to:子链合约地址
		dataStr = "0x89739c5b"
		gas = 0
		gasPrice = 0
		shardingFlag = 1
		to = contractAddress
	} else if funcName == "tx" {
		//to:子链合约地址
		dataStr = toAddr
		shardingFlag = 2
		to = contractAddress
	} else {
		return "", errors.New("没有这个方法名")
	}
	fmt.Println(dataStr)
	bytes, _ := hexutil.Decode(dataStr)

	var rpcClient *Chain3Go.RpcClient
	rpcClient = Chain3Go.NewRpcClient(vnodeIp, netType) //子链

	signStr, err := Chain3Go.SubChainTxSign(
		via,
		netType,
		keyStoreStr,
		password,
		fromAddr,
		to,
		bigAmount,
		big.NewInt(gas),
		big.NewInt(gasPrice),
		shardingFlag,
		bytes,
		nonce,
	)
	if err == nil {
		return rpcClient.Mc().MC_sendRawTransaction(signStr)
	} else {
		return "", err
	}
}

//获取子链块高
func getSubChainHeight(subChainAddress string) (error, uint64) {

	//"http://35.227.40.187:50068/rpc"
	var tmpRpcClient *Chain3Go.RpcClient
	tmpRpcClient = Chain3Go.NewRpcClient(subIp, netType) //子链

	number, err := tmpRpcClient.Mc().ScsRPCMethod_GetBlockNumber(subChainAddress)
	if err != nil {
		return err, 0
	}
	return nil, uint64(number)
}

//获取地址在主链上的nonce
func getAddressNonce(sender string) (uint64, error) {

	var tmpRpcClient *Chain3Go.RpcClient
	tmpRpcClient = Chain3Go.NewRpcClient(vnodeIp, netType) //子链
	number, err := tmpRpcClient.Mc().MC_getTransactionCount(sender, "latest")
	return uint64(number), err
}

//获取地址在子链上的nonce
func getAddressInSubChainNonce(subChainAddress, sender string) (uint64, error) {

	//http://35.227.40.187:50068/rpc
	var tmpRpcClient *Chain3Go.RpcClient
	tmpRpcClient = Chain3Go.NewRpcClient(subIp, netType) //子链
	number, err := tmpRpcClient.Mc().ScsRPCMethod_GetNonce(subChainAddress, sender)
	return uint64(number), err
}

/*
文件ID fileId = 1,
文件hash fileHash = QmWwB2mbmA2UzRrZUH3Es55FAhXWrxbhNYp9RteFJouGxv,
文件名 fileName = "test1.txt",
文件大小 fileSize = 25000,
文件拥有者 fileOwner = 0xceac4cc8524a5f8afa2cca6cbde7270f1942b2d5,
创建时间 createTime = 290192832921,
合约地址 contractAddress = 0x04e3205e01f63e7a3dbbcf8d1795499c89925d3b,
合约存储大小 size = 500000000,
合约剩余存储大小 availableSize = 480000000,
合约占用百分比 percentage = 70
*/
//removeFile, addFile参数拼接
func removeAddFileParameter(fileId, fileSize, createTime, size, availableSize, percentage uint64, pType, fileHash, fileName, fileOwner, contractAddress string) string {

	var number uint64 = 288
	var fileHashNum, fileNameNum uint64 = 1, 1
	num := uint64(len(fileHash))
	if num/32 != 0 {
		number = number + (num/32-1)*64
		fileHashNum = num / 32
		if num%32 != 0 {
			number = number + 64
			fileHashNum = fileHashNum + 1
		}
	}

	num = uint64(len(fileName))
	if num/32 != 0 {
		number = number + (num/32-1)*64
		fileNameNum = num / 32
		if num%32 != 0 {
			number = number + 64
			fileNameNum = fileNameNum + 1
		}
	}

	var tmpStr, reStr string = "", pType

	tmpStr = strconv.FormatUint(fileId, 16)
	reStr = reStr[:] + pieceTogether(tmpStr, "0", 64, true)

	reStr = reStr[:] + "0000000000000000000000000000000000000000000000000000000000000140"

	tmpStr = strconv.FormatUint(uint64(number), 16)
	reStr = reStr[:] + pieceTogether(tmpStr, "0", 64, true)

	tmpStr = strconv.FormatUint(fileSize, 16)
	reStr = reStr[:] + pieceTogether(tmpStr, "0", 64, true)

	reStr = reStr[:] + pieceTogether(fileOwner[2:], "0", 64, true)

	tmpStr = strconv.FormatUint(createTime, 16)
	reStr = reStr[:] + pieceTogether(tmpStr, "0", 64, true)

	reStr = reStr[:] + pieceTogether(contractAddress[2:], "0", 64, true)

	tmpStr = strconv.FormatUint(size, 16)
	reStr = reStr[:] + pieceTogether(tmpStr, "0", 64, true)

	tmpStr = strconv.FormatUint(availableSize, 16)
	reStr = reStr[:] + pieceTogether(tmpStr, "0", 64, true)

	tmpStr = strconv.FormatUint(percentage, 16)
	reStr = reStr[:] + pieceTogether(tmpStr, "0", 64, true)

	tmpStr = strconv.FormatUint(uint64(len(fileHash)), 16)
	reStr = reStr[:] + pieceTogether(tmpStr, "0", 64, true)
	tmpStr = hex.EncodeToString([]byte(fileHash))
	reStr = reStr[:] + pieceTogether(tmpStr, "0", fileHashNum*64, false)

	tmpStr = strconv.FormatUint(uint64(len(fileName)), 16)
	reStr = reStr[:] + pieceTogether(tmpStr, "0", 64, true)
	tmpStr = hex.EncodeToString([]byte(fileName))
	reStr = reStr[:] + pieceTogether(tmpStr, "0", fileNameNum*64, false)

	return reStr
}

/*
合约地址 contractAddress = 0x04e3205e01f63e7a3dbbcf8d1795499c89925d3b
*/
//addLiberumChain, removeLiberumChain参数拼接
func removeAddLiberumChainParameter(pType, contractAddress, contractSize string) string {

	if contractSize != "" {
		contractSizeNumber, err := strconv.ParseUint(contractSize, 10, 64)
		if err != nil {
			return ""
		}
		return pType + pieceTogether(strconv.FormatUint(uint64(contractSizeNumber), 16), "0", 64, true) + pieceTogether(contractAddress[2:], "0", 64, true)
	} else {
		return pType + pieceTogether(contractAddress[2:], "0", 64, true)
	}
}

//拼接字符串 flag:true(前补) flag:false(后补)
func pieceTogether(str, subStr string, number uint64, flag bool) string {

	var reParam string = str
	for i := len(str); uint64(i) < number; i++ {
		if flag {
			reParam = subStr + reParam[:]
		} else {
			reParam = reParam[:] + subStr
		}
	}

	return reParam
}
