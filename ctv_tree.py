#!/usr/bin/env python3
"""
Implementation of a simple OP_CTV transaction that splits the input
into two halves to give a tree-like structure.

          output you're spending from
                     |
             tovault_tx output
                (<H> OP_CTV)
                     |
                 unvault_tx
    (output1_pk OP_CHECKSIG | output2_pk OP_CHECKSIG)
              /               \
        output1_tx           output2_tx
"""

import struct
import hashlib
import sys
import pprint
import typing as t
from dataclasses import dataclass

from bitcoin import SelectParams
from bitcoin.core import (
    CTransaction,
    CMutableTransaction,
    CMutableTxIn,
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
from bitcoin.wallet import CBech32BitcoinAddress
from buidl.hd import HDPrivateKey, PrivateKey
from buidl.ecc import S256Point, Signature
from rpc import BitcoinRPC, JSONRPCError
from clii import App


cli = App(usage=__doc__)

OP_CHECKTEMPLATEVERIFY = script.OP_NOP4

Sats = int
SatsPerByte = int

TxidStr = str
Txid = str
RawTxStr = str

# For use with template transactions.
BLANK_INPUT = CMutableTxIn


@dataclass(frozen=True)
class Coin:
    outpoint: COutPoint
    amount: Sats
    scriptPubKey: bytes
    height: int

    @classmethod
    def from_txid(cls, txid: str, n: int, rpc: BitcoinRPC) -> "Coin":
        tx = rpc.getrawtransaction(txid, True)
        txout = tx["vout"][n]
        return cls(
            COutPoint(txid_to_bytes(txid), n),
            amount=int(txout["value"] * COIN),
            scriptPubKey=bytes.fromhex(txout["scriptPubKey"]["hex"]),
            height=rpc.getblock(tx["blockhash"])["height"],
        )


@dataclass
class Wallet:
    privkey: PrivateKey
    coins: t.List[Coin]
    network: str

    @classmethod
    def generate(cls, seed: bytes, network: str = "regtest") -> "Wallet":
        return cls(
            HDPrivateKey.from_seed(seed, network=network).get_private_key(1),
            [],
            network,
        )

    def fund(self, rpc: BitcoinRPC) -> Coin:
        fund_addr = self.privkey.point.p2wpkh_address(network=self.network)
        rpc.generatetoaddress(110, fund_addr)

        scan = scan_utxos(rpc, fund_addr)
        assert scan["success"]

        for utxo in scan["unspents"]:
            self.coins.append(
                Coin(
                    COutPoint(txid_to_bytes(utxo["txid"]), utxo["vout"]),
                    int(utxo["amount"] * COIN),
                    bytes.fromhex(utxo["scriptPubKey"]),
                    utxo["height"],
                )
            )

        # Earliest coins first.
        self.coins = [
            c for c in sorted(self.coins, key=lambda i: i.height) if c.amount > COIN
        ]
        try:
            return self.coins.pop(0)
        except IndexError:
            raise RuntimeError(
                "Your regtest is out of subsidy - "
                "please wipe the datadir and restart."
            )
        
@dataclass
class CtvTreePlan:
    """
    Template and generate transactions for a one-hop tree structure based on
    OP_CHECKTEMPLATEVERIFY.


          output you're spending from              amount0
                     |
             tovault_tx output                     amount1
                (<H> OP_CTV)
                     |
                 unvault_tx                        amount2
(output1_pk OP_CHECKSIG && output2_pk OP_CHECKSIG)
              /               \
        output1_tx           output2_tx            amount3

    """

    # SEC-encoded public keys associated with various identities in the vault scheme.
    hot_pubkey: S256Point
    cold_pubkey: S256Point
    fees_pubkey: S256Point

    # The coin being committed to the vault.
    coin_in: Coin

    # How many blocks to delay the vault -> hot PK path.
    block_delay: int

    # What percentage of the amount are we taking in fees at each step of the vault?
    # Note this isn't how you'd actually do it (would want to specify feerate),
    # but is a simplification for this demo.
    fees_per_step: Sats = 10000

    def __post_init__(self):
        """
        Plan all (unsigned) vault transactions, which gives us the txid for
        everything.
        """

        def get_txid(tx: CMutableTransaction) -> TxidStr:
            return bytes_to_txid(tx.GetTxid())

        self.tovault_txid: TxidStr = get_txid(self.tovault_tx_unsigned)
        self.tovault_outpoint = COutPoint(txid_to_bytes(self.tovault_txid), 0)

        self.unvault_txid: TxidStr = get_txid(self.unvault_tx_unsigned)
        self.unvault_outpoint1 = COutPoint(txid_to_bytes(self.unvault_txid), 0)
        self.unvault_outpoint2 = COutPoint(txid_to_bytes(self.unvault_txid), 1)

        self.tohot_txid = get_txid(self.tohot_tx_unsigned)
        # self.tocold_txid = get_txid(self.tocold_tx_unsigned)

    def amount_at_step(self, step=0) -> Sats:
        """
        Compute the amount at each step of the vault, per
        "amount[n]" in the diagram above.
        """
        # In reality, you'd compute feerate per step and use that. (TODO)
        amt = self.coin_in.amount - (self.fees_per_step * step)
        assert amt > 0
        return amt

    # tovault transaction
    # -------------------------------

    @property
    def tovault_tx_unsigned(self) -> CMutableTransaction:
        """
        Spend from a P2WPKH output into a new vault.

        The output is a bare OP_CTV script, which consumes less chain space
        than a P2(W)SH.
        """
        tx = CMutableTransaction()
        tx.nVersion = 2
        tx.vin = [CTxIn(self.coin_in.outpoint, nSequence=0)]  # signal for RBF
        tx.vout = [
            CTxOut(
                self.amount_at_step(1),
                CScript([self.unvault_ctv_hash, OP_CHECKTEMPLATEVERIFY]),
            )
        ]
        # print(f"Amount at step 1: {self.amount_at_step(1)}")
        return tx

    def sign_tovault_tx(self, from_privkey: PrivateKey) -> CTransaction:
        tx = self.tovault_tx_unsigned

        spend_from_addr = CBech32BitcoinAddress.from_scriptPubKey(
            CScript(self.coin_in.scriptPubKey)
        )

        # Standard p2wpkh redeemScript
        redeem_script = CScript(
            [
                script.OP_DUP,
                script.OP_HASH160,
                spend_from_addr,
                script.OP_EQUALVERIFY,
                script.OP_CHECKSIG,
            ]
        )

        sighash = script.SignatureHash(
            redeem_script,
            tx,
            0,  # input index
            script.SIGHASH_ALL,
            amount=self.coin_in.amount,
            sigversion=script.SIGVERSION_WITNESS_V0,
        )
        sig = from_privkey.sign(int.from_bytes(sighash, "big")).der() + bytes(
            [script.SIGHASH_ALL]
        )
        wit = [CTxInWitness(CScriptWitness([sig, from_privkey.point.sec()]))]
        tx.wit = CTxWitness(wit)
        return CTransaction.from_tx(tx)

    # unvault transaction
    # -------------------------------

    @property
    def unvault_ctv_hash(self) -> bytes:
        """Return the CTV hash for the unvaulting transaction."""
        return get_standard_template_hash(self.unvault_tx_template, 0)

    @property
    def unvault_tx_template(self) -> CMutableTransaction:
        """
        Return the transaction that initiates the unvaulting process.

        Once this transaction is broadcast, we can either spend to two addresses
        owned by the sender itself

        Note that the particular `vin` value still needs to be filled in, though
        it doesn't matter for the purposes of computing the CTV hash.
        """
        # Used to compute CTV hashes, but not used in any final transactions.
        tx = CMutableTransaction()
        tx.nVersion = 2
        # We can leave this as a dummy input, since the coin we're spending here is
        # encumbered solely by CTV, e.g.
        #
        #   `<H> OP_CTV`
        #
        # and so doesn't require any kind of scriptSig. Subsequently, it won't affect the
        # hash of this transaction.
        # Define two outputs, one for each of the hot and cold keys.
        tx.vin = [BLANK_INPUT()]
        tx.vout = [
            CTxOut(
                self.amount_at_step(2) // 2,
                # Standard P2WSH outputs - 2 outputs, 2 pubkeys.
                CScript([script.OP_0, sha256(self.unvault_redeemScript_output1)]),
            ),
            CTxOut(
                self.amount_at_step(2) // 2,
                CScript([script.OP_0, sha256(self.unvault_redeemScript_output2)]),
            )
        ]
        # print(f"Unvault tx vout: {self.amount_at_step(2) // 2}")
        return tx
    
    @property
    def unvault_redeemScript_output1(self) -> CScript:
        return CScript(
            [
                # fmt: off
                # script.OP_DUP,
                # script.OP_HASH160,
                # self.hot_pubkey.hash160(),
                # script.OP_EQUALVERIFY,
                # script.OP_CHECKSIG,
                self.hot_pubkey.sec(), script.OP_CHECKSIG
                # fmt: on
            ]
        )
    
    @property
    def unvault_redeemScript_output2(self) -> CScript:
        return CScript(
            [
                # fmt: off
                # script.OP_DUP,
                # script.OP_HASH160,
                # self.cold_pubkey.hash160(),
                # script.OP_EQUALVERIFY,
                # script.OP_CHECKSIG,
                self.cold_pubkey.sec(), script.OP_CHECKSIG
                # fmt: on
            ]
        )
    
    @property
    def unvault_tx_unsigned(self) -> CMutableTransaction:
        tx = self.unvault_tx_template
        tx.vin = [CTxIn(self.tovault_outpoint)]
        return CTransaction.from_tx(tx)

    def sign_unvault_tx(self):
        # No signing necessary with a bare CTV output!
        return self.unvault_tx_unsigned
    
    # uncumbering transaction
    # -------------------------------

    @property
    def tohot_tx_template(self) -> CMutableTransaction:
        return p2wpkh_tx_template(
            [BLANK_INPUT()],
            self.amount_at_step(3),
            output1_pay_to_h160=self.hot_pubkey.hash160(),
            output2_pay_to_h160=self.cold_pubkey.hash160(),
            fee_mgmt_pay_to_h160=self.fees_pubkey.hash160(),
        )

    @property
    def tohot_tx_unsigned(self) -> CMutableTransaction:
        """Sends funds to the hot wallet from the unvault transaction."""
        tx = self.tohot_tx_template
        # Important - Make sure the input considers both split outputs from unvault tx
        tx.vin = [
            CTxIn(self.unvault_outpoint1, nSequence=self.block_delay),
            CTxIn(self.unvault_outpoint2, nSequence=self.block_delay)
        ]
        return tx

    def sign_tohot_tx(self, output1_privkey: PrivateKey, output2_privkey: PrivateKey) -> CTransaction:
        """
        Return a finalized, signed transaction moving the vault coins to the 
        two children outputs.
        """
        tx = self.tohot_tx_unsigned

        # Ensure the transaction has two outputs
        assert len(tx.vout) >= 2, "Transaction must have at least two outputs"

        print(f"Hot pubkey compressed: {self.hot_pubkey.sec(compressed=True).hex()}")
        print(f"Cold pubkey compressed: {self.cold_pubkey.sec(compressed=True).hex()}")
        print(f"Hot punkey hash160: {self.hot_pubkey.hash160().hex()}")
        print(f"Cold pubkey hash160: {self.cold_pubkey.hash160().hex()}")

        print(f"Input amount: {self.coin_in.amount / COIN} BTC")
        print(f"Output 1 amount: {tx.vout[0].nValue / COIN} BTC")
        print(f"Output 2 amount: {tx.vout[1].nValue / COIN} BTC")
        print(f"Fee management output: {tx.vout[2].nValue / COIN} BTC")
        print(f"Total output value: {(tx.vout[0].nValue + tx.vout[1].nValue + tx.vout[2].nValue) / COIN} BTC")
        # Split the amount into two equal parts
        half_amount = self.amount_at_step(2) // 2

        print(f"Redeem script for output 1: {self.unvault_redeemScript_output1.hex()}")
        print(f"Redeem script for output 2: {self.unvault_redeemScript_output2.hex()}")
        print(f"Script hash for output 1: {sha256(self.unvault_redeemScript_output1).hex()}")
        print(f"Script hash for output 2: {sha256(self.unvault_redeemScript_output2).hex()}")

        sighash1 = script.SignatureHash(
            self.unvault_redeemScript_output1,
            tx,
            0,
            script.SIGHASH_ALL,
            amount=half_amount, 
            sigversion=script.SIGVERSION_WITNESS_V0,
        )
        
        sig1 = output1_privkey.sign(int.from_bytes(sighash1, "big")).der() + bytes(
            [script.SIGHASH_ALL]
        )
        
        sig_obj = Signature.parse(sig1[:-1])  # Deserialize DER signature
        assert output1_privkey.point.verify(int.from_bytes(sighash1, "big"), sig_obj)


        sighash2 = script.SignatureHash(
            self.unvault_redeemScript_output2,
            tx,
            1, 
            script.SIGHASH_ALL,
            amount=half_amount,
            sigversion=script.SIGVERSION_WITNESS_V0,
        )

        sig2 = output2_privkey.sign(int.from_bytes(sighash2, "big")).der() + bytes(
            [script.SIGHASH_ALL]
        )

        sig_obj = Signature.parse(sig2[:-1])  # Deserialize DER signature
        assert output2_privkey.point.verify(int.from_bytes(sighash2, "big"), sig_obj)

        # Create the witness for the transaction
        witness1 = CScriptWitness([sig1, self.unvault_redeemScript_output1])
        witness2 = CScriptWitness([sig2, self.unvault_redeemScript_output2])
        # Create the witness for the single input that will be split into two outputs
        #witness = CScriptWitness([sig1, self.unvault_redeemScript_output1, sig2, self.unvault_redeemScript_output2])

        #tx.wit = CTxWitness([CTxInWitness(witness)])
        tx.wit = CTxWitness([CTxInWitness(witness1), CTxInWitness(witness2)])

        print(f"Witness for input 1: {witness1}")
        print(f"Witness for input 2: {witness2}")
        print(f"Signature for input 1: {sig1.hex()}")
        print(f"Signature for input 2: {sig2.hex()}")
        print(f"Signature hash for input 1: {sighash1.hex()}")
        print(f"Signature hash for input 2: {sighash2.hex()}")

        return CTransaction.from_tx(tx)


def p2wpkh_tx_template(
    vin: t.List[CTxIn], nValue: int, output1_pay_to_h160: bytes, output2_pay_to_h160: bytes, fee_mgmt_pay_to_h160: bytes
) -> CMutableTransaction:
    """Create a transaction template paying into a P2WPKH."""
    pay_to_script1 = CScript([script.OP_0, output1_pay_to_h160])
    assert pay_to_script1.is_witness_v0_keyhash()

    pay_to_script2 = CScript([script.OP_0, output2_pay_to_h160])
    assert pay_to_script2.is_witness_v0_keyhash()

    pay_to_fee_script = CScript([script.OP_0, fee_mgmt_pay_to_h160])
    assert pay_to_fee_script.is_witness_v0_keyhash()
    HOPEFULLY_NOT_DUST: Sats = 550  # obviously TOOD?

    half_value = nValue // 2 # Split the value between the two outputs

    tx = CMutableTransaction()
    tx.nVersion = 2
    tx.vin = vin
    tx.vout = [
        CTxOut(half_value, pay_to_script1),
        CTxOut(half_value, pay_to_script2),
        # Anchor output for CPFP-based fee bumps
        CTxOut(HOPEFULLY_NOT_DUST, pay_to_fee_script),
    ]
    return tx

def make_color(start, end: str) -> t.Callable[[str], str]:
    def color_func(s: str) -> str:
        return start + t_(s) + end

    return color_func


def esc(*codes: t.Union[int, str]) -> str:
    """
    Produces an ANSI escape code from a list of integers
    """
    return t_("\x1b[{}m").format(t_(";").join(t_(str(c)) for c in codes))


def t_(b: t.Union[bytes, t.Any]) -> str:
    """ensure text type"""
    if isinstance(b, bytes):
        return b.decode()
    return b


FG_END = esc(39)
red = make_color(esc(31), FG_END)
green = make_color(esc(32), FG_END)
yellow = make_color(esc(33), FG_END)
blue = make_color(esc(34), FG_END)
cyan = make_color(esc(36), FG_END)
bold = make_color(esc(1), esc(22))

def no_output(*args, **kwargs):
    pass

@dataclass
class CtvTreeExecutor:
    plan: CtvTreePlan
    rpc: BitcoinRPC
    coin_in: Coin

    log: t.Callable = no_output

    def send_to_vault(self, coin: Coin, spend_key: PrivateKey) -> TxidStr:
        self.log(bold("# Sending to vault\n"))

        self.log(f"Spending coin ({coin.outpoint}) {bold(f'({coin.amount} sats)')}")
        (tx, hx) = self._print_signed_tx(self.plan.sign_tovault_tx, spend_key)

        txid = self.rpc.sendrawtransaction(hx)
        assert txid == tx.GetTxid()[::-1].hex() == self.plan.tovault_txid

        self.log()
        self.log(f"Coins are vaulted at {green(txid)}")
        return txid

    def start_unvault(self) -> TxidStr:
        self.log(bold("# Starting unvault"))

        _, hx = self._print_signed_tx(self.plan.sign_unvault_tx)
        txid = self.rpc.sendrawtransaction(hx)
        self.unvault_outpoint1 = COutPoint(txid_to_bytes(txid), 0)
        self.unvault_outpoint2 = COutPoint(txid_to_bytes(txid), 1)
        return txid
    
    def get_tohot_tx(self, output1_privkey, output2_privkey) -> CTransaction:
        output1_addr = self.plan.hot_pubkey.p2wpkh_address(self.rpc.net_name)
        output2_addr = self.plan.cold_pubkey.p2wpkh_address(self.rpc.net_name)
        self.log(bold(f"# Sweep to children addresses ({output1_addr}) and ({output2_addr})"))
        print(f"Sweeping to {output1_addr} and {output2_addr}")
        print(f"Output1 key: {output1_privkey} Output2 key: {output2_privkey}")

        output1_pubkey = output1_privkey.point
        output2_pubkey = output2_privkey.point

        # Print the public key in SEC format (compressed or uncompressed)
        print("Public key (uncompressed):", output1_pubkey.sec(compressed=False).hex())
        print("Public key output1 (compressed):", output1_pubkey.sec(compressed=True).hex())
        print("Public key (uncompressed):", output2_pubkey.sec(compressed=False).hex())
        print("Public key output2 (compressed):", output2_pubkey.sec(compressed=True).hex())

        (tx, _) = self._print_signed_tx(self.plan.sign_tohot_tx, output1_privkey, output2_privkey)
        return tx

    def _print_signed_tx(
        self, signed_txn_fnc, *args, **kwargs
    ) -> t.Tuple[CTransaction, RawTxStr]:
        """Plan a finalized transaction and print its broadcast information."""
        tx = signed_txn_fnc(*args, **kwargs)
        hx = tx.serialize().hex()

        self.log(bold(f"\n## Transaction {yellow(tx.GetTxid()[::-1].hex())}"))
        self.log(f"{tx}")
        self.log()
        self.log("### Raw hex")
        self.log(hx)

        return tx, hx
    
def generateblocks(rpc: BitcoinRPC, n: int = 1, addr: str = None) -> t.List[str]:
    if not addr:
        addr = (
            HDPrivateKey.from_seed(b"yaddayah")
            .get_private_key(1)
            .point.p2wpkh_address(network=rpc.net_name)
        )
    return rpc.generatetoaddress(n, addr)


def sha256(s) -> bytes:
    return hashlib.sha256(s).digest()


def ser_compact_size(l) -> bytes:
    r = b""
    if l < 253:
        r = struct.pack("B", l)
    elif l < 0x10000:
        r = struct.pack("<BH", 253, l)
    elif l < 0x100000000:
        r = struct.pack("<BI", 254, l)
    else:
        r = struct.pack("<BQ", 255, l)
    return r


def ser_string(s) -> bytes:
    return ser_compact_size(len(s)) + s


def get_standard_template_hash(tx: CTransaction, nIn: int) -> bytes:
    r = b""
    r += struct.pack("<i", tx.nVersion)
    r += struct.pack("<I", tx.nLockTime)
    vin = tx.vin or []
    vout = tx.vout or []
    if any(inp.scriptSig for inp in vin):
        r += sha256(b"".join(ser_string(inp.scriptSig) for inp in vin))
    r += struct.pack("<I", len(tx.vin))
    r += sha256(b"".join(struct.pack("<I", inp.nSequence) for inp in vin))
    r += struct.pack("<I", len(tx.vout))
    r += sha256(b"".join(out.serialize() for out in vout))
    r += struct.pack("<I", nIn)
    return sha256(r)


def txid_to_bytes(txid: str) -> bytes:
    """Convert the txids output by Bitcoin Core (little endian) to bytes."""
    return bytes.fromhex(txid)[::-1]


def bytes_to_txid(b: bytes) -> str:
    """Convert big-endian bytes to Core-style txid str."""
    return b[::-1].hex()


def to_outpoint(txid: TxidStr, n: int) -> COutPoint:
    return COutPoint(txid_to_bytes(txid), n)


def scan_utxos(rpc, addr):
    return rpc.scantxoutset("start", [f"addr({addr})"])


@dataclass
class CtvTreeScenario:
    """Instantiate everything needed to do vault operations."""

    network: str
    rpc: BitcoinRPC

    from_wallet: Wallet
    fee_wallet: Wallet
    output1_wallet: Wallet
    output2_wallet: Wallet
    coin_in: Coin

    plan: CtvTreePlan
    exec: CtvTreeExecutor

    @classmethod
    def from_network(cls, network: str, seed: bytes, coin: Coin = None, **plan_kwargs):
        SelectParams(network)
        from_wallet = Wallet.generate(b"from-" + seed)
        fee_wallet = Wallet.generate(b"fee-" + seed)
        output2_wallet = Wallet.generate(b"output2-" + seed)
        output1_wallet = Wallet.generate(b"output1-" + seed)

        rpc = BitcoinRPC(net_name=network)
        coin = coin or from_wallet.fund(rpc)
        plan = CtvTreePlan(
            output1_wallet.privkey.point,
            output2_wallet.privkey.point,
            fee_wallet.privkey.point,
            coin,
            **plan_kwargs,
        )

        return cls(
            network,
            rpc,
            from_wallet=from_wallet,
            fee_wallet=fee_wallet,
            output1_wallet=output1_wallet,
            output2_wallet=output2_wallet,
            coin_in=coin,
            plan=plan,
            exec=CtvTreeExecutor(plan, rpc, coin),
        )

    @classmethod
    def for_demo(cls, original_coin_txid: TxidStr = None) -> 'CtvTreeScenario':
        """
        Instantiate a scenario for the demo, optionally resuming an existing
        vault using the txid of the coin we spent into it.
        """
        coin_in = None
        if original_coin_txid:
            # We're resuming a vault
            rpc = BitcoinRPC(net_name="regtest")
            coin_in = Coin.from_txid(original_coin_txid, 0, rpc)
            print(f"Resuming with coin of value: {coin_in.amount}")

        # TODO - Check blockdelay
        c = CtvTreeScenario.from_network(
            "regtest", seed=b"demo", coin=coin_in, block_delay=0
        )

        c.exec.log = lambda *args, **kwargs: print(*args, file=sys.stderr, **kwargs)

        return c


@cli.cmd
def encumber():
    """
    Returns the txid of the coin spent into the CTV, which is used to resume CTV
    operations.
    """
    c = CtvTreeScenario.for_demo()
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
def generate_blocks(n: int):
    rpc = BitcoinRPC(net_name="regtest")
    pprint.pprint(generateblocks(rpc, n))

def _broadcast_final(c: CtvTreeScenario, tx: CTransaction):
    print()
    title = f"spending to {red('children')}"

    if input(f"Broadcast transaction {title}? (y/n) ") == 'y':
        try:
            print(f"tx details: {tx}")
            txid = c.rpc.sendrawtransaction(tx.serialize().hex())
        except JSONRPCError as e:
            if 'missingorspent' in e.msg:
                print("!!! can't broadcast - unvault txn hasn't been seen yet")
                sys.exit(3)
            else:
                raise

        print(f"Broadcast done: {green(txid)}")
        print()
        pprint.pprint(c.rpc.gettxout(txid, 0))

if __name__ == "__main__":
    cli.run()