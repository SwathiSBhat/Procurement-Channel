## Steps using Bitcoin cli to use CTV

- Start bitcoind and load wallet
- Generate blocks for inital funds
```
bitcoin-cli -regtest generatetoaddress 101 "$(bitcoin-cli -regtest getnewaddress)"
```
- Generate new destination address for CTV
```
DEST_ADDRESS=$(bitcoin-cli -regtest getnewaddress)
echo $DEST_ADDRESS
```
- Compute the template hash for CTV 
```
TEMPLATE_SCRIPT=$(bitcoin-cli -regtest getnewaddress | xargs bitcoin-cli -regtest getaddressinfo | jq -r '.scriptPubKey')
TEMPLATE_HASH=$(echo -n $TEMPLATE_SCRIPT | xxd -r -p | sha256sum | awk '{print $1}')
echo $TEMPLATE_HASH
```
- Choose a funding tx by running `bitcoin-cli -regtest listunspent`
```
TXID=036d144eedf5cbb635ab0d2454befdace5138ca90ef3e72626554519d9691004
VOUT=0
```
- Create CTV which is of the form "20 + TEMPLATE_HASH + C0"
```
CTV_SCRIPT="20${TEMPLATE_HASH}C0"
```
- Create the raw transaction. Make sure the amount in change address + dest is almost equal to the funding tx. Else, everything else will go as fee and it will result in a high fee which will fail.
```
CHANGE_ADDRESS=$(bitcoin-cli -regtest getnewaddress)
RAW_TX=$(bitcoin-cli -regtest createrawtransaction \
  "[{\"txid\":\"$TXID\",\"vout\":$VOUT}]" \
  "{\"$DEST_ADDRESS\":0.09,\"$CHANGE_ADDRESS\":0.007,\"data\":\"$CTV_SCRIPT\"}")
```
- Sign the transaction
```
SIGNED_TX=$(bitcoin-cli -regtest signrawtransactionwithwallet $RAW_TX | jq -r '.hex')
```
- Broadcast the transaction
```
bitcoin-cli -regtest sendrawtransaction $SIGNED_TX
```
- Generate a block to confirm the transaction
```
bitcoin-cli -regtest generatetoaddress 1 "$(bitcoin-cli -regtest getnewaddress)"
```

- Create spending transaction
```
SPEND_TX=$(bitcoin-cli -regtest createrawtransaction \
  "[{\"txid\":\"$TXID\",\"vout\":$VOUT}]" \
  "{\"$DEST_ADDRESS\":0.09,\"$CHANGE_ADDRESS\":0.007,\"data\":\"$CTV_SCRIPT\"}")
```

- Sign spending tx
```
SPEND_SIGNED_TX=$(bitcoin-cli -regtest signrawtransactionwithwallet $SPEND_TX | jq -r '.hex')
```

- Broadcast spending tx
```
bitcoin-cli -regtest sendrawtransaction $SPEND_SIGNED_TX
```

- Gives error:
error code: -27
error message:
Transaction outputs already in utxo set
