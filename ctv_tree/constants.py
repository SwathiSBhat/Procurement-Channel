from pathlib import Path

Sats = int
SatsPerByte = int

TxidStr = str
Txid = str
RawTxStr = str

EQUIVOCATION_STATE_FILE = Path(__file__).parent / "equivocation_state.json"
PENALIZING_TXID_FILE = Path(__file__).parent / "penalizing_txid.txt"
