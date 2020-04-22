# Chain3Go - Chain3 Go API

LBR Go API was built for LBR chain. It was developed from LBR RPC API, which can be used to develop Ðapp to LBR chain. It supports both VNODE and SCS methods for LBR.

## Chain3Go Installation

### setup $GOPATH

```
export GOPATH=/Users/[user]/go
```

### go get

```bash
go get -u github.com/LBRChain/Chain3Go
```

## LBR Configuration

### Install LBR

Download latest LBR Vnode and SCS Releases from here: https://github.com/LBRChain/LBR-core/releases

### Run LBR

Run LBR vnode on testnet
```
./LBR --testnet
```
Run LBR scs on testnet
```
./scsserver
```

Create new accounts and send transactions

```
mc.coinbase
mc.accounts
personal.newAccount()
passphrase:
repeat passphrase:

miner.start()
--wait a few seconds
miner.stop()

personal.unlockAccount("0x18833df6ba69b4d50acc744e8294d128ed8db1f1")
mc.sendTransaction({from: '0x18833df6ba69b4d50acc744e8294d128ed8db1f1', to: '0x2a022eb956d1962d867dcebd8fed6ae71ee4385a', value: chain3.toSha(12, "LBR")}) 
```

## Chain3Go Execution
```bash
go run main.go
```

### Requirements

* go ^1.8.3

[Go installation instructions.](https://golang.org/doc/install)

