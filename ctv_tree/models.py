import sys
import pprint
import typing as t
import authenticator
import uuid

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
from utils import ( 
    scan_utxos, 
    txid_to_bytes, 
    bytes_to_txid,
    get_standard_template_hash,
    p2wpkh_tx_template,
    sha256,
    no_output,
    bold,
    yellow,
    green,
    load_equivocation_state,
    save_equivocation_state,
    load_penalizing_txid,
    save_penalizing_txid,
)
from constants import Sats, TxidStr, RawTxStr

# For use with template transactions.
BLANK_INPUT = CMutableTxIn
OP_CHECKTEMPLATEVERIFY = script.OP_NOP4

from dataclasses import dataclass

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
    def __init__(self, privkey, coins, network):
        self.privkey = privkey
        self.network = network
        self._unspent_coins = coins.copy()  # Track unspent separately
        self._spent_outpoints = set()  # Track spent UTXOs


    @classmethod
    def generate(cls, seed: bytes, network: str = "regtest") -> "Wallet":
        return cls(
            HDPrivateKey.from_seed(seed, network=network).get_private_key(1),
            [],
            network,
        )

    def fund(self, rpc: BitcoinRPC, blocks_to_mine: int = 110) -> Coin:
        self._unspent_coins = [
            c for c in self._unspent_coins 
            if c.outpoint not in self._spent_outpoints
        ]
        
        if not self._unspent_coins:
            # Mine fresh coins if none available
            fund_addr = self.privkey.point.p2wpkh_address(network=self.network)
            rpc.generatetoaddress(blocks_to_mine, fund_addr)
            
            # Rescan to get ALL current UTXOs
            scan = scan_utxos(rpc, fund_addr)
            assert scan["success"]
            
            self._unspent_coins = [
                Coin(
                    COutPoint(txid_to_bytes(utxo["txid"]), utxo["vout"]),
                    int(utxo["amount"] * COIN),
                    bytes.fromhex(utxo["scriptPubKey"]),
                    utxo["height"],
                )
                for utxo in scan["unspents"]
                if COutPoint(txid_to_bytes(utxo["txid"]), utxo["vout"]) not in self._spent_outpoints
            ]
            
        if not self._unspent_coins:
            raise RuntimeError("No spendable coins after funding")
            
        # Return oldest unspent coin
        coin = min(self._unspent_coins, key=lambda c: c.height)
        self._spent_outpoints.add(coin.outpoint)
        return coin
        
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
        output1_tx          output2_tx            amount3
    (A_pk OP_CHECKSIG)   (B_pk OP_CHECKSIG)
              |               |
        spending_tx1     spending_tx2             amount4

    """

    # SEC-encoded public keys associated with various identities in the vault scheme.
    hot_pubkey: S256Point
    cold_pubkey: S256Point
    fees_pubkey: S256Point
    clientA_pubkey: S256Point
    clientB_pubkey: S256Point
    penalty_pubkey: S256Point # Public key for the penalizing transaction

    # The coin being committed to the vault.
    coin_in: Coin
    
    # The coin used for penalizing equivocation
    penalize_coin: Coin

    # How many blocks to delay the vault -> hot PK path.
    block_delay: int

    # What percentage of the amount are we taking in fees at each step of the vault?
    # Note this isn't how you'd actually do it (would want to specify feerate),
    # but is a simplification for this demo.
    fees_per_step: Sats = 10000
    
    # Authenticator instances used for non-equivocating contracts
    # auth - Authenticator instance from secret key used by sender to generate assertion for ct,st pair
    # auth_dpk - Authenticator instance from derived public key used by recipient to verify assertion and extract secret key in case of equivocation
    auth: t.Optional[authenticator.Authenticator] = None
    auth_dpk: t.Optional[authenticator.Authenticator] = None

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
        
        # TODO - Store penalizing txid here
        # self.tocold_txid = get_txid(self.tocold_tx_unsigned)
        
        # Store a map of context (leaf_index) to statement (recipient_uuid)
        self.context_to_statement: dict[str, any] = load_equivocation_state()
        print(f"Loaded equivocation state: {self.context_to_statement}")

    def amount_at_step(self, step=0) -> Sats:
        """
        Compute the amount at each step of the vault, per
        "amount[n]" in the diagram above.
        """
        amt = self.coin_in.amount - (self.fees_per_step * step)
        assert amt > 0
        return amt
    
    @property 
    def to_penalize_tx_unsigned(self) -> CMutableTransaction:
        """
        Create a transaction that spends from the penalize_coin to the penalty_pubkey
        """
        tx = CMutableTransaction()
        tx.nVersion = 2
        tx.vin = [CTxIn(self.penalize_coin.outpoint, nSequence=0)]
        
        return tx
    
    def sign_penalizing_tx(self, from_privkey: PrivateKey) -> CTransaction:
        tx = self.to_penalize_tx_unsigned

        penalize_amount = self.penalize_coin.amount - self.fees_per_step
        # This implements:
        #   IF 
        #     <penalty_pubkey> CHECKSIGVERIFY 
        #   ELSE 
        #     <200> CHECKSEQUENCEVERIFY DROP 
        #     <from_pubkey> CHECKSIG
        #   ENDIF
        penalize_script = CScript([
            script.OP_IF,
            self.penalty_pubkey.sec(), script.OP_CHECKSIGVERIFY,
            script.OP_ELSE,
            200, script.OP_CHECKSEQUENCEVERIFY, script.OP_DROP,
            from_privkey.point.sec(), script.OP_CHECKSIG,
            script.OP_ENDIF
        ])
        
        tx.vout = [
            CTxOut(penalize_amount,
                   CScript([script.OP_0, sha256(penalize_script)]))
        ]
        
        spend_from_addr = CBech32BitcoinAddress.from_scriptPubKey(
        CScript(self.penalize_coin.scriptPubKey)
        )
        
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
            amount=self.penalize_coin.amount,
            sigversion=script.SIGVERSION_WITNESS_V0,
        )
    
        sig = from_privkey.sign(int.from_bytes(sighash, "big")).der() + bytes(
            [script.SIGHASH_ALL]
        )
        
        wit = [CTxInWitness(CScriptWitness([sig, from_privkey.point.sec()]))]
        tx.wit = CTxWitness(wit)
        
        print(f"Created penalizing transaction: {green(bytes_to_txid(tx.GetTxid()))}")
        print(f"Can be claimed by penalty wallet immediately if equivocation detected")
        print(f"Will return to from_wallet after 200 blocks if unclaimed")
        
        return CTransaction.from_tx(tx)

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
        return tx
    
    @property
    def unvault_redeemScript_output1(self) -> CScript:
        return CScript(
            [
                # fmt: off
                self.hot_pubkey.sec(), script.OP_CHECKSIG
                # fmt: on
            ]
        )
    
    @property
    def unvault_redeemScript_output2(self) -> CScript:
        return CScript(
            [
                # fmt: off
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

    # Verifying equivocation
    # -------------------------------
    def get_verify_equivocation(self, context, statement):
        """
        If 2 different statements are provided for same context, reveal secret key
        """
        context_bytes = context.to_bytes(8, 'big')
        statement_bytes = statement.encode('utf-8')
        
        # Reject if context length > 8 bytes
        if len(context_bytes) > 8:
            raise ValueError("Context length must be exactly 8 bytes")
        
        if len(context_bytes) < 8:
            context_bytes = context_bytes.ljust(8, b'\x00')
            
        # Sender sends tau for current context, statement pair
        print(f"Context length: {len(context_bytes)}, statement length: {len(statement_bytes)}")
        tau = self.auth.authenticate(context_bytes, statement_bytes)
        
        # Recipient verifies the assertion
        # TODO - Ideally, recipient should also check time t < T in penalizing transaction
        is_valid = self.auth_dpk.verify(tau, context_bytes, statement_bytes)
        
        if not is_valid:
            raise ValueError("Invalid assertion")
        
        # Print context_to_statement dict:
        print(f"Current context_to_statement: {self.context_to_statement}")
        dict_key = str(context)
        print(f"Checking for context {dict_key} in context_to_statement {dict_key in self.context_to_statement}")
        
        # Check for equivocation
        if dict_key in self.context_to_statement:
            if self.context_to_statement[dict_key] != statement:
                print(f"Existing statement: {self.context_to_statement[dict_key]}, current statement: {statement}")
                # Reveal secret key
                # TODO - Tau should ideally be stored in the dict as well
                # Need to figure out how to serialize it
                tau_previous = self.auth.authenticate(context_bytes, self.context_to_statement[dict_key])
                self.auth_dpk.extract(
                    tau_previous, 
                    tau, 
                    context_bytes, 
                    self.context_to_statement[dict_key], 
                    statement_bytes)
                print(f"Secret key revealed for context {context}")
                extracted_sk = self.auth_dpk.getDsk()
                print(f"Extracted secret key: {extracted_sk}")
                # TODO - Broadcast transaction to get funds
        else:
            self.context_to_statement[context] = statement_bytes
            save_equivocation_state(self.context_to_statement)
            print(f"Tau stored for context {context}")
        return
        
@dataclass
class CtvTreeExecutor:
    plan: CtvTreePlan
    rpc: BitcoinRPC
    coin_in: Coin

    log: t.Callable = no_output
    
    def init_penalizing_tx(self, spend_key: PrivateKey) -> TxidStr:
        """
        Create a time-locked penalizing transaction that:
        - Spends from the penalize_coin (funded by from_wallet)
        - Can be claimed by penalize_wallet immediately if equivocation is detected
        - Or returns to from_wallet after 200 blocks (timeout)
        """
        (tx, raw_tx) = self._print_signed_tx(self.plan.sign_penalizing_tx, spend_key)
        txid = self.rpc.sendrawtransaction(raw_tx)
        save_penalizing_txid(txid)
        

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
    
    def verify_equivocation(self, recipient: str, leaf_index: int):
        """
        Verify that the transaction has not been double-spent using non-equivocating
        contracts.
        """
        context = leaf_index
        # statement = recipient + '_' + random number
        statement = recipient + '_' + str(uuid.uuid1())
        
        self.log(bold(f"# Verifying equivocation for context: {context} and statement: {statement}"))
        self.log()
        
        self.plan.get_verify_equivocation(context, statement)
        return

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
    
@dataclass
class CtvTreeScenario:
    """Instantiate everything needed to do vault operations."""

    network: str
    rpc: BitcoinRPC

    from_wallet: Wallet
    # Generate a wallet for penalizing sender for equivocation
    penalize_wallet: Wallet
    fee_wallet: Wallet
    output1_wallet: Wallet
    output2_wallet: Wallet
    A_wallet: Wallet
    B_wallet: Wallet
    coin_in: Coin

    plan: CtvTreePlan
    exec: CtvTreeExecutor
    # This will be used by the sender to assert ct,st pair
    auth: t.Optional[authenticator.Authenticator] = None  # Authenticator instance
    # This will be used by the recipient to verify the assertion and extract secret key in case of equivocation
    auth_dpk: t.Optional[authenticator.Authenticator] = None  # Authenticator instance from derived public key

    @classmethod
    def from_network(cls, network: str, seed: bytes, coin: Coin = None, **plan_kwargs):
        SelectParams(network)
        # Use deterministic seeds to ensure same addresses are generated across each cli cmd
        from_wallet = Wallet.generate(b"from-" + seed)
        penalize_wallet = Wallet.generate(b"penalize-" + seed)
        fee_wallet = Wallet.generate(b"fee-" + seed)
        output2_wallet = Wallet.generate(b"output2-" + seed)
        output1_wallet = Wallet.generate(b"output1-" + seed)
        # Client A wallet 
        A_wallet = Wallet.generate(b"A-" + seed)
        # Client B wallet
        B_wallet = Wallet.generate(b"B-" + seed)

        rpc = BitcoinRPC(net_name=network)
        # Fund wallet during intialization for penalizing equivocation
        if coin is None:
            penalize_coins = from_wallet.fund(rpc, 220)
            print(f"Wallet funded with {penalize_coins.amount} sats for penalizing equivocation")
        else:
            penalizing_txid = load_penalizing_txid()
            penalize_coins = Coin.from_txid(penalizing_txid, 0, rpc) 
            print(f"Penalizing txid: {penalizing_txid}")
            
        coin = coin or from_wallet.fund(rpc)
           
        plan = CtvTreePlan(
            output1_wallet.privkey.point,
            output2_wallet.privkey.point,
            fee_wallet.privkey.point,
            A_wallet.privkey.point,
            B_wallet.privkey.point,
            penalize_wallet.privkey.point,
            coin,
            penalize_coins,
            **plan_kwargs,
        )

        return cls(
            network,
            rpc,
            from_wallet=from_wallet,
            penalize_wallet=penalize_wallet,
            fee_wallet=fee_wallet,
            output1_wallet=output1_wallet,
            output2_wallet=output2_wallet,
            A_wallet=A_wallet,
            B_wallet=B_wallet,
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

        # TODO - Check blockdelay
        c = CtvTreeScenario.from_network(
            "regtest", seed=b"demo", coin=coin_in, block_delay=0
        )
        c.exec.log = lambda *args, **kwargs: print(*args, file=sys.stderr, **kwargs)
        
        privkey_bytes = c.penalize_wallet.privkey.secret.to_bytes(32, 'big')
        c.auth = authenticator.Authenticator(privkey_bytes)
        print("Authenticator initialized with secret key.")
        
        # Get derived public key
        dpk = c.auth.getDpk()
        print(f"Derived public key (dpk): {dpk}")
        c.auth_dpk = authenticator.Authenticator(dpk)
        
        c.plan.auth = c.auth
        c.plan.auth_dpk = c.auth_dpk
            
        return c

def _broadcast_final(c: CtvTreeScenario, tx: CTransaction):
    print()

    if input(f"Broadcast transaction? (y/n) ") == 'y':
        try:
            print(f"Transaction to broadcast: {tx}")
            txid = c.rpc.sendrawtransaction(tx.serialize().hex())
        except JSONRPCError as e:
            if 'missingorspent' in e.msg:
                print("!!! can't broadcast - txn hasn't been seen yet")
                sys.exit(3)
            else:
                raise

        print(f"Broadcast done: {green(txid)}")
        print()
        pprint.pprint(c.rpc.gettxout(txid, 0))