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
    c.exec.init_penalizing_tx(c.from_wallet.privkey)
    
    # Mine blocks to confirm the penalizing tx
    rpc = BitcoinRPC(net_name="regtest")
    generateblocks(rpc, 10)
    
    c.exec.send_to_vault(c.coin_in, c.from_wallet.privkey)

    original_coin_txid = c.coin_in.outpoint.hash[::-1].hex()
    print(bold(f"Coins are vaulted at {original_coin_txid}\n"))

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
    tx = c.exec.start_unvault()
    _broadcast_final(c, tx)

@cli.cmd
def to_children(original_coin_txid: TxidStr):
    """
    Spend the vaulted coin to the two children outputs.
    """
    c = CtvTreeScenario.for_demo(original_coin_txid)
    tx = c.exec.get_tohot_tx(c.output1_wallet.privkey, c.output2_wallet.privkey)
    # Broadcast the tx that satisfies the CTV on the main chain.
    parent_tx = c.exec.start_unvault()
    print(f"Parent tx: {parent_tx}")
    # Send array of parent txns to broadcast
    parent_txns = [parent_tx]
    _broadcast_final(c, tx, parent_txns)

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
    spending_key = c.output1_wallet.privkey if leaf_index == 0 else c.output2_wallet.privkey
    # Set recipient address based on leaf index (0 or 1)
    recipient_pubkey = c.A_wallet.privkey.point if leaf_index == 0 else c.B_wallet.privkey.point
    # TODO - This can be replaced by a unique identifier for each recipient
    recipient_name = "A" if leaf_index == 0 else "B"
    
    tx = c.exec.spend_leaves(
        spending_key,
        recipient_pubkey,
        leaf_index,
    )
    
    # Use non-equivocating contracts to verify that the tx is not double-spent
    c.exec.verify_equivocation(recipient_name, leaf_index)
    
    # Parent transactions to broadcast if not already done
    # NOTE - the order of broadcasting the transactions is important. Start with the top and then move down.
    parent_txns = [c.exec.start_unvault(), c.exec.get_tohot_tx(c.output1_wallet.privkey, c.output2_wallet.privkey)]
    
    _broadcast_final(c, tx, parent_txns)

@cli.cmd
def generate_blocks(n: int):
    rpc = BitcoinRPC(net_name="regtest")
    pprint.pprint(generateblocks(rpc, n))