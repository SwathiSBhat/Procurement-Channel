from clii import App
from models import CtvTreeScenario, _broadcast_final
from utils import (
    TxidStr,
    txid_to_bytes,
    generateblocks,
    bold,
    clear_equivocation_state,
    clear_penalizing_txid,
)
import sys
import pprint
from rpc import BitcoinRPC
from bitcoin.core import (
    CMutableTransaction,
    CTxIn,
    CTxOut,
    CScript,
    COutPoint,
    CTxWitness,
    CTxInWitness,
    CScriptWitness,
    COIN,
)
from bitcoin.core import script

cli = App(usage=__doc__)

@cli.cmd
def encumber():
    """
    1. Clear contents of equivocation state file.
    2. Initializes the penalizing transaction to prevent spender from double-spending
    3. Returns the txid of the coin spent into the CTV, which is used to resume CTV
    operations.
    """
    c = CtvTreeScenario.for_demo()
    
    print(bold("# Clearing out equivocation state and resetting penalizing txid\n"))
    clear_equivocation_state()
    clear_penalizing_txid()
    
    print(bold("# Creating transaction to penalize equivocation\n"))
    # TODO - Create transaction to penalize equivocation
    #c.exec.init_penalizing_tx(c.from_wallet.privkey)
    
    c.exec.send_to_vault(c.coin_in, c.from_wallet.privkey)
    # TODO - Uncomment this later
    # assert not c.exec.search_for_unvault()
    original_coin_txid = c.coin_in.outpoint.hash[::-1].hex()
    print(original_coin_txid)

@cli.cmd
def unencumber(original_coin_txid: TxidStr):
    """
    Start the unvault process with an existing vault, based on the orignal coin
    input.

    We assume the original coin has a vout index of 0.

    Args:
        original_coin_txid: the txid of the original coin we spent into the vault.
    """
    c = CtvTreeScenario.for_demo(original_coin_txid)
    c.exec.start_unvault()

@cli.cmd
def to_children(original_coin_txid: TxidStr):
    """
    Spend the vaulted coin to the two children outputs.
    """
    c = CtvTreeScenario.for_demo(original_coin_txid)
    tx = c.exec.get_tohot_tx(c.output1_wallet.privkey, c.output2_wallet.privkey)
    # Broadcast the tx that satisfies the CTV on the main chain.
    _broadcast_final(c, tx)

@cli.cmd
def spend_leaf_outputs(original_coin_txid: TxidStr, leaf_index: int):
    """
    Spend the output in leaf nodes to the respective recipients 
    Currently, the tree has just 2 leaves => index 0 or 1
    If index = 0 => spend to A's wallet
    If index = 1 => spend to B's wallet
    """
    if leaf_index not in [0, 1]:
        print("Invalid leaf index. Must be 0 or 1")
        sys.exit(1)
    
    c = CtvTreeScenario.for_demo(original_coin_txid)
    
    # Set spend address based on leaf index (0 or 1)
    spending_wallet = c.output1_wallet if leaf_index == 0 else c.output2_wallet
    # Set recipient address based on leaf index (0 or 1)
    recipient_pubkey = c.A_wallet.privkey.point if leaf_index == 0 else c.B_wallet.privkey.point
    # TODO - This can be replaced by a unique identifier for each recipient
    recipient_name = "A" if leaf_index == 0 else "B"
    
    ctv_tx = c.plan.tohot_txid
    print(f"Spending output from tx: {ctv_tx}")
    
    # Use non-equivocating contracts to verify that the tx is not double-spent
    c.exec.verify_equivocation(recipient_name, leaf_index)

    tx = CMutableTransaction()
    tx.nVersion = 2
    tx.vin = [CTxIn(COutPoint(txid_to_bytes(ctv_tx), leaf_index), nSequence=0)]
    
    # Output sending to A's wallet
    ctv_raw_tx = c.rpc.getrawtransaction(ctv_tx, True)
    input_amount = int(ctv_raw_tx["vout"][leaf_index]["value"] * COIN)
    # Output = input - fees (10000 sats)
    tx.vout = [CTxOut(input_amount - 10000, CScript([script.OP_0, recipient_pubkey.hash160()]))]
    
    # Generate signature for P2WPKH
    script_code = CScript([script.OP_DUP, script.OP_HASH160, 
                          spending_wallet.privkey.point.hash160(), 
                          script.OP_EQUALVERIFY, script.OP_CHECKSIG])
    
    sighash = script.SignatureHash(
        script_code,
        tx,
        0,
        script.SIGHASH_ALL,
        amount=input_amount,
        sigversion=script.SIGVERSION_WITNESS_V0,
    )
    
    sig = spending_wallet.privkey.sign(int.from_bytes(sighash, 'big')).der() + bytes([script.SIGHASH_ALL])
    
    # Witness must be EXACTLY [signature, pubkey] for P2WPKH
    tx.wit = CTxWitness([CTxInWitness(CScriptWitness([sig, spending_wallet.privkey.point.sec()]))])
    
    _broadcast_final(c, tx)

@cli.cmd
def generate_blocks(n: int):
    rpc = BitcoinRPC(net_name="regtest")
    pprint.pprint(generateblocks(rpc, n))