# ChainGo - Chain Go API

TORO Go API was built for TORO chain. It was developed from TORO RPC API, which can be used to develop Ðapp to TORO chain. It supports both VNODE and SCS methods for TORO.

## ChainGo Installation

### setup $GOPATH

```
export GOPATH=/Users/[user]/go
```

### go get

```bash
go get -u github.com/TOROnetwork/Chain
```

## TORO Configuration

### Install TORO

Download latest TORO Vnode and SCS Releases from here: https://github.com/TOROnetwork/Chain

### Run TORO

Run TORO vnode on testnet
```
./TORO --testnet
```
Run TORO scs on testnet
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

## ChainGo Execution
```bash
go run main.go
```

### Requirements

* go ^1.8.3

[Go installation instructions.](https://golang.org/doc/install)

