import struct
import hashlib
from rpc import BitcoinRPC
from buidl.hd import HDPrivateKey
from bitcoin.core import (
    CTransaction,
    CMutableTransaction,
    CTxIn,
    CTxOut,
    CScript,
    COutPoint,
)
import typing as t
from bitcoin.core import script
from constants import Sats, TxidStr, EQUIVOCATION_STATE_FILE, PENALIZING_TXID_FILE
import json
import base64
from typing import Dict

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

leaf_node_amount = 0

def p2wpkh_tx_template(
    vin: t.List[CTxIn], nValue: int, output1_pay_to_h160: bytes, output2_pay_to_h160: bytes, fee_mgmt_pay_to_h160: bytes
) -> CMutableTransaction:
    global leaf_node_amount
    """Create a transaction template paying into a P2WPKH."""
    pay_to_script1 = CScript([script.OP_0, output1_pay_to_h160])
    assert pay_to_script1.is_witness_v0_keyhash()

    pay_to_script2 = CScript([script.OP_0, output2_pay_to_h160])
    assert pay_to_script2.is_witness_v0_keyhash()

    pay_to_fee_script = CScript([script.OP_0, fee_mgmt_pay_to_h160])
    assert pay_to_fee_script.is_witness_v0_keyhash()
    HOPEFULLY_NOT_DUST: Sats = 550  # obviously TOOD?

    half_value = nValue // 2 # Split the value between the two outputs
    leaf_node_amount = half_value

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

def save_equivocation_state(state: Dict[str, bytes]) -> None:
    """Save dict with string keys and bytes values to JSON file."""
    with open(EQUIVOCATION_STATE_FILE, "w") as f:
        json.dump(
            {k: base64.b64encode(v).decode('utf-8') for k, v in state.items()},
            f,
            indent=2
        )

def load_equivocation_state() -> Dict[str, bytes]:
    """Load dict with string keys and bytes values from JSON file."""
    if not EQUIVOCATION_STATE_FILE.exists() or EQUIVOCATION_STATE_FILE.stat().st_size == 0:
        return {}
    
    with open(EQUIVOCATION_STATE_FILE, "r") as f:
        try:
            return {
                k: base64.b64decode(v.encode('utf-8'))
                for k, v in json.load(f).items()
            }
        except (json.JSONDecodeError, base64.binascii.Error):
            return {}
        
def clear_equivocation_state() -> None:
    """Delete the contents of the equivocation state file."""
    with open(EQUIVOCATION_STATE_FILE, "w") as f:
        f.write("")

def save_penalizing_txid(txid: TxidStr) -> None:
    """Save the penalizing txid to a file."""
    with open(PENALIZING_TXID_FILE, "w") as f:
        f.write(txid)
        
def load_penalizing_txid() -> TxidStr:
    """Load the penalizing txid from a file."""
    with open(PENALIZING_TXID_FILE, "r") as f:
        return f.read().strip()
    
def clear_penalizing_txid() -> None:
    """Delete the contents of the penalizing txid file."""
    with open(PENALIZING_TXID_FILE, "w") as f:
        f.write("")
        
# Test status
SUCCESS = green("✓") 
FAIL = red("✗")    