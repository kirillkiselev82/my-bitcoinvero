#!/usr/bin/env python3
# MyBot / UTXO Core v1
# Stage 2 preflight — consensus-aware raw block / transaction decoder audit.
#
# This is NOT the full Stage 2 extractor.
# It re-reads representative canonical blocks through the frozen Stage 1
# locator and validates transaction parsing, txid/wtxid, merkle roots,
# witness commitments, coinbase structure, CompactSize canonicality,
# and exact block boundaries before the full windowed decoder is released.

import csv
import fcntl
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
from pathlib import Path

BASE = Path("/opt/mybot_data/etl/utxo_core_v1")
DATADIR = Path("/opt/mybot_data/bitcoin")
BLOCKS = DATADIR / "blocks"

MANIFEST = BASE / "manifests/canonical_chain_0_617698.tsv"
MANIFEST_SHA = Path(str(MANIFEST) + ".sha256")
LOCATOR = BASE / "stage/block_locator_0_617698.tsv"
LOCATOR_SHA = Path(str(LOCATOR) + ".sha256")
STAGE1_META = BASE / "stage/block_locator_0_617698.meta.json"
SEMANTIC_AUDIT = BASE / "stage/block_locator_0_617698.semantic_audit.json"
SEMANTIC_AUDIT_SHA = Path(str(SEMANTIC_AUDIT) + ".sha256")
XOR_FILE = BLOCKS / "xor.dat"
DATADIR_LOCK = DATADIR / ".lock"

EXPECTED_MANIFEST_SHA256 = (
    "5227507e9b38fbdb63040c1e197cdfb9b39cc2d054c6744722113206c4847161"
)
EXPECTED_LOCATOR_SHA256 = (
    "0e045ecee898095f1a35789c2d21efccc737b390e998c2a0c79c6bf659c516ed"
)
EXPECTED_SEMANTIC_AUDIT_SHA256 = (
    "422e652f850cbdf0f2c546b852a1d9e97dbb093c87e2c4cc46e3bedb154c4662"
)
EXPECTED_XOR_HEX = "2af1c3e24315d54b"
EXPECTED_XOR_SHA256 = (
    "b5e50a9b6a79fce708c9fcfb62a76c512aec637192961c94fd99ffe051b9d6e7"
)
EXPECTED_END_HASH = (
    "000000000000000000095ad21001856998971c4951123d14276b5f13c45e83d8"
)
EXPECTED_STAGE1_SCRIPT_SHA256 = (
    "d80ac36c2eb6490aa7aabdb70ebf4eee45f18160946e8e3812256a8c6669522b"
)

# Independently captured from Bitcoin Core RPC for height 617698.
EXPECTED_TARGET_PREV_HASH = (
    "000000000000000000067461ebbba39991e7b65aa8c51ed2e3805834d6a74c1a"
)
EXPECTED_TARGET_MERKLE_ROOT = (
    "51d342fa7f79d8c02cf397b77e3060f29045c95dc4a488b0a21c76da12399308"
)
EXPECTED_TARGET_NTX = 313
EXPECTED_TARGET_SIZE = 116637
EXPECTED_TARGET_STRIPPED_SIZE = 87793
EXPECTED_TARGET_WEIGHT = 380016
# Mainnet SegWit activation block.
SEGWIT_ACTIVE_HEIGHT = 481824

# Representative points:
# - genesis / immediate successor
# - historical BIP30 duplicate-txid blocks
# - SegWit activation boundary
# - mature post-SegWit
# - two heights from the old source-forensics problem ranges
# - final target boundary
SAMPLE_HEIGHTS = (
    0,
    1,
    91842,
    91880,
    481824,
    481825,
    500000,
    506733,
    617557,
    617697,
    617698,
)

WITNESS_COMMITMENT_PREFIX = bytes.fromhex("6a24aa21a9ed")
MAINNET_MAGIC = bytes.fromhex("f9beb4d9")
MAX_BLOCK_SERIALIZED_SIZE = 4_000_000
MAX_BLOCK_WEIGHT = 4_000_000
WITNESS_SCALE_FACTOR = 4
MAX_MONEY = 21_000_000 * 100_000_000
BLK_FILE_RE = re.compile(r"^blk([0-9]{5})\.dat$")


def sha256d(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def display_hash(raw_digest):
    return raw_digest[::-1].hex()


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(8 * 1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def xor_at(raw, absolute_offset, key):
    return bytes(
        b ^ key[(absolute_offset + i) % len(key)]
        for i, b in enumerate(raw)
    )


def encode_compact_size(value):
    if value < 0:
        raise ValueError("negative CompactSize")
    if value < 253:
        return bytes([value])
    if value <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", value)
    if value <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", value)
    if value <= 0xFFFFFFFFFFFFFFFF:
        return b"\xff" + struct.pack("<Q", value)
    raise ValueError("CompactSize overflow")


class Reader:
    __slots__ = ("data", "pos", "label")

    def __init__(self, data, label):
        self.data = data
        self.pos = 0
        self.label = label

    def remaining(self):
        return len(self.data) - self.pos

    def read(self, n):
        if n < 0:
            raise ValueError("negative read")
        end = self.pos + n
        if end > len(self.data):
            raise RuntimeError(
                f"{self.label}: truncated read at offset={self.pos}, "
                f"need={n}, remaining={self.remaining()}"
            )
        out = self.data[self.pos:end]
        self.pos = end
        return out

    def u8(self):
        return self.read(1)[0]

    def u32(self):
        return struct.unpack("<I", self.read(4))[0]

    def i64(self):
        return struct.unpack("<q", self.read(8))[0]

    def compact_size(self):
        first = self.u8()

        if first < 253:
            return first

        if first == 253:
            value = struct.unpack("<H", self.read(2))[0]
            if value < 253:
                raise RuntimeError(
                    f"{self.label}: non-canonical CompactSize 0xfd "
                    f"for value={value}"
                )
            return value

        if first == 254:
            value = struct.unpack("<I", self.read(4))[0]
            if value < 0x10000:
                raise RuntimeError(
                    f"{self.label}: non-canonical CompactSize 0xfe "
                    f"for value={value}"
                )
            return value

        value = struct.unpack("<Q", self.read(8))[0]
        if value < 0x100000000:
            raise RuntimeError(
                f"{self.label}: non-canonical CompactSize 0xff "
                f"for value={value}"
            )
        return value

    def varbytes(self):
        size = self.compact_size()
        if size > self.remaining():
            raise RuntimeError(
                f"{self.label}: varbytes length={size} "
                f"> remaining={self.remaining()}"
            )
        return self.read(size)


def parse_input(r):
    prev_txid_raw = r.read(32)
    prev_vout = r.u32()
    script_sig = r.varbytes()
    sequence = r.u32()

    return {
        "prev_txid_raw": prev_txid_raw,
        "prev_txid": prev_txid_raw[::-1].hex(),
        "prev_vout": prev_vout,
        "script_sig": script_sig,
        "sequence": sequence,
    }


def parse_output(r):
    value = r.i64()
    script_pubkey = r.varbytes()

    return {
        "value": value,
        "script_pubkey": script_pubkey,
    }


def parse_transaction(r, tx_index):
    start = r.pos
    version_raw = r.read(4)
    version = struct.unpack("<I", version_raw)[0]

    # Mirror Bitcoin Core's UnserializeTransaction:
    # first deserialize vin; an empty vin may be the witness dummy marker.
    first_vin_count = r.compact_size()
    flags = 0

    inputs = []
    input_raw_parts = []
    outputs = []
    output_raw_parts = []

    if first_vin_count == 0:
        flags = r.u8()

        if flags != 0:
            vin_count = r.compact_size()

            # Minimum serialized input:
            # 32 txid + 4 vout + 1 script length + 4 sequence.
            if vin_count > r.remaining() // 41 + 1:
                raise RuntimeError(
                    f"{r.label}: tx[{tx_index}] "
                    f"impossible vin_count={vin_count}"
                )

            for _ in range(vin_count):
                before = r.pos
                item = parse_input(r)
                after = r.pos
                inputs.append(item)
                input_raw_parts.append(r.data[before:after])

            vout_count = r.compact_size()

            if vout_count > r.remaining() // 9 + 1:
                raise RuntimeError(
                    f"{r.label}: tx[{tx_index}] "
                    f"impossible vout_count={vout_count}"
                )

            for _ in range(vout_count):
                before = r.pos
                item = parse_output(r)
                after = r.pos
                outputs.append(item)
                output_raw_parts.append(r.data[before:after])
        else:
            # This exactly follows Core deserialization semantics:
            # empty vin + zero flags leaves both vin and vout empty.
            # CheckTransaction rejects this later as a consensus-invalid tx.
            vin_count = 0
            vout_count = 0

    else:
        vin_count = first_vin_count

        if vin_count > r.remaining() // 41 + 1:
            raise RuntimeError(
                f"{r.label}: tx[{tx_index}] "
                f"impossible vin_count={vin_count}"
            )

        for _ in range(vin_count):
            before = r.pos
            item = parse_input(r)
            after = r.pos
            inputs.append(item)
            input_raw_parts.append(r.data[before:after])

        vout_count = r.compact_size()

        if vout_count > r.remaining() // 9 + 1:
            raise RuntimeError(
                f"{r.label}: tx[{tx_index}] "
                f"impossible vout_count={vout_count}"
            )

        for _ in range(vout_count):
            before = r.pos
            item = parse_output(r)
            after = r.pos
            outputs.append(item)
            output_raw_parts.append(r.data[before:after])

    witnesses = [[] for _ in range(vin_count)]
    has_witness = False
    segwit_serialized = bool(flags & 1)

    if flags & 1:
        flags ^= 1

        for vin_index in range(vin_count):
            stack_count = r.compact_size()

            # Every witness item needs at least its own CompactSize prefix.
            if stack_count > r.remaining() + 1:
                raise RuntimeError(
                    f"{r.label}: tx[{tx_index}] vin[{vin_index}] "
                    f"impossible witness item count={stack_count}"
                )

            stack = []
            for _ in range(stack_count):
                stack.append(r.varbytes())

            witnesses[vin_index] = stack
            if stack:
                has_witness = True

        if not has_witness:
            raise RuntimeError(
                f"{r.label}: tx[{tx_index}] superfluous witness record"
            )

    # Core rejects any remaining optional-data bits before nLockTime.
    if flags:
        raise RuntimeError(
            f"{r.label}: tx[{tx_index}] unknown transaction "
            f"optional flags=0x{flags:02x}"
        )

    locktime_raw = r.read(4)
    locktime = struct.unpack("<I", locktime_raw)[0]
    end = r.pos

    full_serialization = r.data[start:end]

    # TX_NO_WITNESS serialization of the parsed transaction.
    stripped = bytearray()
    stripped += version_raw
    stripped += encode_compact_size(vin_count)
    for part in input_raw_parts:
        stripped += part
    stripped += encode_compact_size(vout_count)
    for part in output_raw_parts:
        stripped += part
    stripped += locktime_raw
    stripped = bytes(stripped)

    txid_raw = sha256d(stripped)
    wtxid_raw = (
        sha256d(full_serialization)
        if has_witness
        else txid_raw
    )

    is_coinbase = (
        vin_count == 1
        and inputs[0]["prev_txid_raw"] == b"\x00" * 32
        and inputs[0]["prev_vout"] == 0xFFFFFFFF
    )

    return {
        "start": start,
        "end": end,
        "size": end - start,
        "stripped_size": len(stripped),
        "version": version,
        "locktime": locktime,
        "vin_count": vin_count,
        "vout_count": vout_count,
        "inputs": inputs,
        "outputs": outputs,
        "witnesses": witnesses,
        "segwit_serialized": segwit_serialized,
        "has_witness": has_witness,
        "is_coinbase": is_coinbase,
        "txid_raw": txid_raw,
        "wtxid_raw": wtxid_raw,
        "txid": display_hash(txid_raw),
        "wtxid": display_hash(wtxid_raw),
    }


def check_transaction_context_free(tx, label, tx_index):
    """Mirror Bitcoin Core CheckTransaction checks that need no UTXO context."""
    where = f"{label}: tx[{tx_index}]"

    if tx["vin_count"] == 0:
        raise RuntimeError(f"{where}: bad-txns-vin-empty")

    if tx["vout_count"] == 0:
        raise RuntimeError(f"{where}: bad-txns-vout-empty")

    if tx["stripped_size"] * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT:
        raise RuntimeError(f"{where}: bad-txns-oversize")

    total_value = 0

    for vout_index, out in enumerate(tx["outputs"]):
        value = out["value"]

        if value < 0:
            raise RuntimeError(
                f"{where}: vout[{vout_index}] bad-txns-vout-negative"
            )

        if value > MAX_MONEY:
            raise RuntimeError(
                f"{where}: vout[{vout_index}] bad-txns-vout-toolarge"
            )

        total_value += value

        if total_value < 0 or total_value > MAX_MONEY:
            raise RuntimeError(
                f"{where}: bad-txns-txouttotal-toolarge"
            )

    seen_prevouts = set()

    for vin_index, txin in enumerate(tx["inputs"]):
        outpoint = (txin["prev_txid_raw"], txin["prev_vout"])

        if outpoint in seen_prevouts:
            raise RuntimeError(
                f"{where}: vin[{vin_index}] bad-txns-inputs-duplicate"
            )

        seen_prevouts.add(outpoint)

    if tx["is_coinbase"]:
        script_len = len(tx["inputs"][0]["script_sig"])

        if script_len < 2 or script_len > 100:
            raise RuntimeError(
                f"{where}: bad-cb-length={script_len}"
            )

    else:
        for vin_index, txin in enumerate(tx["inputs"]):
            is_null = (
                txin["prev_txid_raw"] == b"\x00" * 32
                and txin["prev_vout"] == 0xFFFFFFFF
            )

            if is_null:
                raise RuntimeError(
                    f"{where}: vin[{vin_index}] bad-txns-prevout-null"
                )

    return total_value


def merkle_root(leaves):
    if not leaves:
        return b"\x00" * 32, False

    level = list(leaves)
    mutated = False

    while len(level) > 1:
        # Core's mutation detection checks equal *real* sibling pairs before
        # duplicating an odd final leaf.
        for i in range(0, len(level) - 1, 2):
            if level[i] == level[i + 1]:
                mutated = True

        if len(level) & 1:
            level.append(level[-1])

        level = [
            sha256d(level[i] + level[i + 1])
            for i in range(0, len(level), 2)
        ]

    return level[0], mutated


def witness_commitment_index(coinbase):
    found = -1

    for idx, out in enumerate(coinbase["outputs"]):
        script = out["script_pubkey"]
        if (
            len(script) >= 38
            and script[:6] == WITNESS_COMMITMENT_PREFIX
        ):
            found = idx

    return found


def validate_witness_commitment(txs, label, segwit_active):
    any_witness = any(tx["has_witness"] for tx in txs)
    coinbase = txs[0]
    commitment_index = witness_commitment_index(coinbase)
    pattern_detected = commitment_index >= 0

    # Before SegWit activation, a commitment-looking OP_RETURN is just script
    # bytes. Core does not interpret it as a witness commitment, and any actual
    # witness serialization in the block is invalid.
    if not segwit_active:
        if any_witness:
            raise RuntimeError(
                f"{label}: unexpected witness data before SegWit activation"
            )

        return {
            "segwit_active": False,
            "pattern_detected": pattern_detected,
            "present": False,
            "valid": True,
            "index": None,
            "any_witness": False,
        }

    # SegWit is active. If a recognized commitment is present, validate it.
    if commitment_index >= 0:
        if not coinbase["has_witness"]:
            raise RuntimeError(
                f"{label}: witness commitment present but coinbase "
                f"has no witness reserved value"
            )

        coinbase_witness = coinbase["witnesses"][0]

        if (
            len(coinbase_witness) != 1
            or len(coinbase_witness[0]) != 32
        ):
            raise RuntimeError(
                f"{label}: coinbase witness reserved value must be "
                f"exactly one 32-byte item"
            )

        witness_leaves = [b"\x00" * 32]
        witness_leaves.extend(tx["wtxid_raw"] for tx in txs[1:])

        witness_root, _ = merkle_root(witness_leaves)
        reserved = coinbase_witness[0]
        calculated = sha256d(witness_root + reserved)

        script = coinbase["outputs"][commitment_index]["script_pubkey"]
        committed = script[6:38]

        if calculated != committed:
            raise RuntimeError(
                f"{label}: witness commitment mismatch "
                f"expected={committed.hex()} "
                f"calculated={calculated.hex()}"
            )

        return {
            "segwit_active": True,
            "pattern_detected": True,
            "present": True,
            "valid": True,
            "index": commitment_index,
            "any_witness": any_witness,
        }

    # SegWit is active but there is no commitment. That is allowed only when
    # the block contains no witness data.
    if any_witness:
        raise RuntimeError(
            f"{label}: witness data present but no witness commitment"
        )

    return {
        "segwit_active": True,
        "pattern_detected": False,
        "present": False,
        "valid": True,
        "index": None,
        "any_witness": False,
    }


def parse_block(block, height, expected_hash, expected_prev):
    label = f"height={height}"

    if len(block) < 81:
        raise RuntimeError(f"{label}: block too short: {len(block)}")

    if len(block) > MAX_BLOCK_SERIALIZED_SIZE:
        raise RuntimeError(
            f"{label}: block serialized size too large: {len(block)}"
        )

    r = Reader(block, label)
    header = r.read(80)

    header_hash = display_hash(sha256d(header))
    if header_hash != expected_hash:
        raise RuntimeError(
            f"{label}: block hash mismatch "
            f"manifest={expected_hash} decoded={header_hash}"
        )

    prev_hash = header[4:36][::-1].hex()
    if prev_hash != expected_prev:
        raise RuntimeError(
            f"{label}: previousblockhash mismatch "
            f"expected={expected_prev} decoded={prev_hash}"
        )

    header_merkle_raw = header[36:68]

    tx_count = r.compact_size()
    if tx_count == 0:
        raise RuntimeError(f"{label}: zero transactions")

    # CheckBlock includes vtx.size()*4 <= MAX_BLOCK_WEIGHT.
    if tx_count * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT:
        raise RuntimeError(
            f"{label}: transaction count exceeds block consensus limit"
        )

    txs = []

    for tx_index in range(tx_count):
        tx = parse_transaction(r, tx_index)
        check_transaction_context_free(tx, label, tx_index)
        txs.append(tx)

    if r.pos != len(block):
        raise RuntimeError(
            f"{label}: block parser boundary mismatch "
            f"parsed={r.pos} block_size={len(block)} "
            f"remaining={r.remaining()}"
        )

    if not txs[0]["is_coinbase"]:
        raise RuntimeError(f"{label}: transaction 0 is not coinbase")

    for idx, tx in enumerate(txs[1:], start=1):
        if tx["is_coinbase"]:
            raise RuntimeError(
                f"{label}: extra coinbase transaction at index={idx}"
            )

    root, mutated = merkle_root([tx["txid_raw"] for tx in txs])

    if mutated:
        raise RuntimeError(f"{label}: mutated transaction merkle tree")

    if root != header_merkle_raw:
        raise RuntimeError(
            f"{label}: transaction merkle root mismatch "
            f"header={header_merkle_raw[::-1].hex()} "
            f"calculated={root[::-1].hex()}"
        )

    stripped_block_size = (
        80
        + len(encode_compact_size(tx_count))
        + sum(tx["stripped_size"] for tx in txs)
    )

    if stripped_block_size * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT:
        raise RuntimeError(
            f"{label}: stripped block size exceeds consensus limit "
            f"stripped_size={stripped_block_size}"
        )

    segwit_active = height >= SEGWIT_ACTIVE_HEIGHT
    witness = validate_witness_commitment(
        txs,
        label,
        segwit_active=segwit_active,
    )

    block_weight = stripped_block_size * 3 + len(block)

    if block_weight > MAX_BLOCK_WEIGHT:
        raise RuntimeError(
            f"{label}: block weight exceeds consensus limit "
            f"weight={block_weight}"
        )

    witness_tx_count = sum(1 for tx in txs if tx["has_witness"])
    non_coinbase_witness_tx_count = sum(
        1 for tx in txs[1:] if tx["has_witness"]
    )
    txid_wtxid_diff_count = sum(
        1 for tx in txs if tx["txid_raw"] != tx["wtxid_raw"]
    )

    result = {
        "height": height,
        "hash": header_hash,
        "prev_hash": prev_hash,
        "block_size": len(block),
        "stripped_size": stripped_block_size,
        "weight": block_weight,
        "tx_count": tx_count,
        "witness_tx_count": witness_tx_count,
        "non_coinbase_witness_tx_count": non_coinbase_witness_tx_count,
        "txid_wtxid_diff_count": txid_wtxid_diff_count,
        "segwit_serialized_tx_count": sum(
            1 for tx in txs if tx["segwit_serialized"]
        ),
        "merkle_root": root[::-1].hex(),
        "witness_commitment": witness,
        "first_txid": txs[0]["txid"],
        "last_txid": txs[-1]["txid"],
        "first_tx": txs[0],
    }

    if height == 617698:
        expected = {
            "hash": EXPECTED_END_HASH,
            "prev_hash": EXPECTED_TARGET_PREV_HASH,
            "merkle_root": EXPECTED_TARGET_MERKLE_ROOT,
            "tx_count": EXPECTED_TARGET_NTX,
            "block_size": EXPECTED_TARGET_SIZE,
            "stripped_size": EXPECTED_TARGET_STRIPPED_SIZE,
            "weight": EXPECTED_TARGET_WEIGHT,
        }

        for key, expected_value in expected.items():
            if result[key] != expected_value:
                raise RuntimeError(
                    f"{label}: independent Core anchor {key} mismatch "
                    f"expected={expected_value} actual={result[key]}"
                )

        if not result["witness_commitment"]["present"]:
            raise RuntimeError(
                f"{label}: expected active witness commitment"
            )

    return result


def require_core_stopped_and_lock():
    proc = subprocess.run(
        ["systemctl", "is-active", "bitcoind"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    state = proc.stdout.strip()

    if state != "inactive":
        raise RuntimeError(
            f"bitcoind service must be inactive, got {state!r}"
        )

    pgrep = subprocess.run(
        ["pgrep", "-x", "bitcoind"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )

    if pgrep.returncode == 0:
        raise RuntimeError("bitcoind process exists outside systemd")

    if pgrep.returncode not in (0, 1):
        raise RuntimeError(
            f"pgrep bitcoind failed with rc={pgrep.returncode}"
        )

    # Never create Bitcoin Core's .lock as root. If it is absent, fail closed
    # rather than risk creating a root-owned mode-0600 file that can prevent
    # the bitcoin service user from opening its datadir later.
    if not DATADIR_LOCK.is_file():
        raise RuntimeError(
            f"Bitcoin Core datadir lock file is missing: {DATADIR_LOCK}"
        )

    lock_fd = os.open(DATADIR_LOCK, os.O_RDWR)

    try:
        fcntl.lockf(
            lock_fd,
            fcntl.LOCK_EX | fcntl.LOCK_NB,
            0,
            0,
            os.SEEK_SET,
        )
    except OSError as exc:
        os.close(lock_fd)
        raise RuntimeError(
            f"cannot acquire Bitcoin Core datadir lock: "
            f"{DATADIR_LOCK}: {exc}"
        ) from exc

    # Close the TOCTOU gap between the process check and lock acquisition.
    pgrep_after = subprocess.run(
        ["pgrep", "-x", "bitcoind"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )

    if pgrep_after.returncode == 0:
        os.close(lock_fd)
        raise RuntimeError(
            "bitcoind appeared while acquiring the datadir lock"
        )

    if pgrep_after.returncode not in (0, 1):
        os.close(lock_fd)
        raise RuntimeError(
            f"second pgrep bitcoind failed with rc={pgrep_after.returncode}"
        )

    return lock_fd


def verify_sha(path, sidecar, expected=None):
    if not path.is_file():
        raise RuntimeError(f"missing artifact: {path}")
    if not sidecar.is_file():
        raise RuntimeError(f"missing checksum: {sidecar}")

    actual = sha256_file(path)
    parts = sidecar.read_text(encoding="utf-8").strip().split()
    if not parts or parts[0].lower() != actual:
        raise RuntimeError(f"checksum sidecar mismatch: {path}")
    if expected is not None and actual != expected:
        raise RuntimeError(
            f"pinned SHA mismatch: {path}\n"
            f"expected={expected}\nactual  ={actual}"
        )
    return actual


def load_manifest():
    needed = set(SAMPLE_HEIGHTS)
    needed.update(h - 1 for h in SAMPLE_HEIGHTS if h > 0)

    expected = {}

    with MANIFEST.open("r", encoding="ascii") as f:
        reader = csv.DictReader(f, delimiter="\t")

        if reader.fieldnames != ["height", "block_hash"]:
            raise RuntimeError(
                f"unexpected manifest columns: {reader.fieldnames!r}"
            )

        for row in reader:
            h = int(row["height"])

            if h in needed:
                block_hash = row["block_hash"]

                if (
                    len(block_hash) != 64
                    or any(
                        c not in "0123456789abcdef"
                        for c in block_hash
                    )
                ):
                    raise RuntimeError(
                        f"invalid manifest hash at height={h}"
                    )

                expected[h] = block_hash

    missing = needed - expected.keys()

    if missing:
        raise RuntimeError(
            f"manifest sample heights missing: {sorted(missing)}"
        )

    return expected


def load_locator(manifest):
    rows = {}

    with LOCATOR.open("r", encoding="ascii") as f:
        reader = csv.DictReader(f, delimiter="\t")

        required_columns = {
            "height",
            "block_hash",
            "prev_hash",
            "blk_file",
            "file_number",
            "record_offset",
            "block_offset",
            "block_size",
            "record_size",
        }

        if set(reader.fieldnames or []) != required_columns:
            raise RuntimeError(
                f"unexpected locator columns: {reader.fieldnames!r}"
            )

        for row in reader:
            h = int(row["height"])

            if h not in SAMPLE_HEIGHTS:
                continue

            if h in rows:
                raise RuntimeError(
                    f"duplicate locator sample height={h}"
                )

            if row["block_hash"] != manifest[h]:
                raise RuntimeError(
                    f"locator/manifest hash mismatch at height={h}"
                )

            expected_prev = (
                "0" * 64 if h == 0 else manifest[h - 1]
            )

            if row["prev_hash"] != expected_prev:
                raise RuntimeError(
                    f"locator prev_hash mismatch at height={h}"
                )

            match = BLK_FILE_RE.fullmatch(row["blk_file"])

            if match is None:
                raise RuntimeError(
                    f"invalid locator blk_file at height={h}: "
                    f"{row['blk_file']!r}"
                )

            file_number = int(row["file_number"])

            if int(match.group(1)) != file_number:
                raise RuntimeError(
                    f"locator file number mismatch at height={h}"
                )

            record_offset = int(row["record_offset"])
            block_offset = int(row["block_offset"])
            block_size = int(row["block_size"])
            record_size = int(row["record_size"])

            if record_offset < 0:
                raise RuntimeError(
                    f"negative record offset at height={h}"
                )

            if block_offset != record_offset + 8:
                raise RuntimeError(
                    f"locator block_offset mismatch at height={h}"
                )

            if not (81 <= block_size <= MAX_BLOCK_SERIALIZED_SIZE):
                raise RuntimeError(
                    f"locator block_size invalid at height={h}: "
                    f"{block_size}"
                )

            if record_size != block_size + 8:
                raise RuntimeError(
                    f"locator record_size mismatch at height={h}"
                )

            rows[h] = row

    missing = set(SAMPLE_HEIGHTS) - rows.keys()

    if missing:
        raise RuntimeError(
            f"locator sample heights missing: {sorted(missing)}"
        )

    return rows


def read_block(row, key):
    path = BLOCKS / row["blk_file"]
    record_offset = int(row["record_offset"])
    block_offset = int(row["block_offset"])
    block_size = int(row["block_size"])

    if not path.is_file():
        raise RuntimeError(f"missing block file: {path}")

    if block_offset != record_offset + 8:
        raise RuntimeError(
            f"invalid physical locator offsets for {path}"
        )

    if block_size <= 0 or block_size > MAX_BLOCK_SERIALIZED_SIZE:
        raise RuntimeError(
            f"invalid locator block_size={block_size} for {path}"
        )

    file_size = path.stat().st_size

    if record_offset + 8 + block_size > file_size:
        raise RuntimeError(
            f"locator record extends beyond file: {path}"
        )

    with path.open("rb") as f:
        f.seek(record_offset)
        raw_storage = f.read(8)

        f.seek(block_offset)
        raw_block = f.read(block_size)

    if len(raw_storage) != 8 or len(raw_block) != block_size:
        raise RuntimeError(f"short physical read: {path}")

    storage = xor_at(raw_storage, record_offset, key)

    if storage[:4] != MAINNET_MAGIC:
        raise RuntimeError(
            f"bad mainnet magic: {path}@{record_offset}"
        )

    stored_size = struct.unpack("<I", storage[4:8])[0]

    if stored_size != block_size:
        raise RuntimeError(
            f"locator/storage size mismatch: "
            f"locator={block_size} storage={stored_size}"
        )

    return xor_at(raw_block, block_offset, key)


def self_test():
    # CompactSize boundary values.
    values = (
        0,
        1,
        252,
        253,
        254,
        255,
        0xFFFF,
        0x10000,
        0xFFFFFFFF,
        0x100000000,
    )

    for value in values:
        encoded = encode_compact_size(value)
        r = Reader(encoded, "compact-selftest")
        decoded = r.compact_size()

        if decoded != value or r.remaining() != 0:
            raise RuntimeError("CompactSize selftest failed")

    # Explicit non-canonical encodings must fail.
    bad = (
        b"\xfd\xfc\x00",
        b"\xfe\xff\xff\x00\x00",
        b"\xff\xff\xff\xff\xff\x00\x00\x00\x00",
    )

    for raw in bad:
        try:
            Reader(raw, "bad-compact").compact_size()
        except RuntimeError:
            pass
        else:
            raise RuntimeError(
                "non-canonical CompactSize was accepted"
            )

    # Minimal synthetic legacy coinbase-like transaction.
    legacy = (
        struct.pack("<I", 1)
        + b"\x01"
        + b"\x00" * 32
        + struct.pack("<I", 0xFFFFFFFF)
        + b"\x02\x00\x00"
        + struct.pack("<I", 0xFFFFFFFF)
        + b"\x01"
        + struct.pack("<q", 50 * 100_000_000)
        + b"\x01\x51"
        + struct.pack("<I", 0)
    )

    r = Reader(legacy, "legacy-selftest")
    tx = parse_transaction(r, 0)

    if r.remaining() or not tx["is_coinbase"] or tx["has_witness"]:
        raise RuntimeError("legacy transaction selftest failed")

    if tx["txid"] != tx["wtxid"]:
        raise RuntimeError("legacy txid/wtxid selftest failed")

    check_transaction_context_free(
        tx,
        "legacy-selftest",
        0,
    )

    # Mirror Core's empty-vin + zero-flags deserialization path, then ensure
    # the separate context-free validator rejects it.
    empty = (
        struct.pack("<I", 1)
        + b"\x00"
        + b"\x00"
        + struct.pack("<I", 0)
    )

    r = Reader(empty, "empty-selftest")
    empty_tx = parse_transaction(r, 0)

    if r.remaining() != 0:
        raise RuntimeError("empty transaction parser selftest failed")

    try:
        check_transaction_context_free(
            empty_tx,
            "empty-selftest",
            0,
        )
    except RuntimeError as exc:
        if "bad-txns-vin-empty" not in str(exc):
            raise
    else:
        raise RuntimeError(
            "empty transaction passed context-free validation"
        )

    # Minimal synthetic witness transaction with one input and witness item.
    wit = (
        struct.pack("<I", 2)
        + b"\x00\x01"
        + b"\x01"
        + bytes.fromhex("11" * 32)
        + struct.pack("<I", 0)
        + b"\x00"
        + struct.pack("<I", 0xFFFFFFFE)
        + b"\x01"
        + struct.pack("<q", 1)
        + b"\x00"
        + b"\x01"
        + b"\x01\x01"
        + struct.pack("<I", 0)
    )

    r = Reader(wit, "witness-selftest")
    tx = parse_transaction(r, 0)

    if (
        r.remaining()
        or not tx["has_witness"]
        or not tx["segwit_serialized"]
    ):
        raise RuntimeError("witness transaction selftest failed")

    if tx["txid"] == tx["wtxid"]:
        raise RuntimeError(
            "witness txid unexpectedly equals wtxid"
        )

    check_transaction_context_free(
        tx,
        "witness-selftest",
        0,
    )

    # Merkle single-leaf identity and odd-leaf duplication.
    leaf = sha256d(b"x")
    root, mutated = merkle_root([leaf])

    if root != leaf or mutated:
        raise RuntimeError("single-leaf merkle selftest failed")

    a, b, c = sha256d(b"a"), sha256d(b"b"), sha256d(b"c")
    root, mutated = merkle_root([a, b, c])
    expected = sha256d(sha256d(a + b) + sha256d(c + c))

    if root != expected or mutated:
        raise RuntimeError("odd merkle selftest failed")

    _, mutated = merkle_root([a, a])

    if not mutated:
        raise RuntimeError("merkle mutation selftest failed")

    # Synthetic witness commitment: active context validates it.
    reserved = b"\x00" * 32
    witness_root, _ = merkle_root([b"\x00" * 32])
    commitment = sha256d(witness_root + reserved)

    fake_coinbase = {
        "has_witness": True,
        "witnesses": [[reserved]],
        "outputs": [{
            "script_pubkey": (
                WITNESS_COMMITMENT_PREFIX + commitment
            )
        }],
        "wtxid_raw": sha256d(b"fake-coinbase"),
    }

    witness_result = validate_witness_commitment(
        [fake_coinbase],
        "witness-commitment-selftest",
        segwit_active=True,
    )

    if not witness_result["present"]:
        raise RuntimeError(
            "active witness commitment selftest failed"
        )

    # Same bytes before activation must not be interpreted as a commitment;
    # actual witness data must make the block invalid.
    fake_no_witness = dict(fake_coinbase)
    fake_no_witness["has_witness"] = False
    fake_no_witness["witnesses"] = [[]]

    pre_result = validate_witness_commitment(
        [fake_no_witness],
        "pre-segwit-pattern-selftest",
        segwit_active=False,
    )

    if (
        pre_result["present"]
        or not pre_result["pattern_detected"]
    ):
        raise RuntimeError(
            "pre-SegWit commitment-pattern selftest failed"
        )

    try:
        validate_witness_commitment(
            [fake_coinbase],
            "pre-segwit-witness-selftest",
            segwit_active=False,
        )
    except RuntimeError as exc:
        if "unexpected witness" not in str(exc):
            raise
    else:
        raise RuntimeError(
            "pre-SegWit witness data was accepted"
        )


def main():
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except (AttributeError, ValueError):
        pass

    print("=== MYBOT STAGE 2 DECODER PREFLIGHT v2.2 ===")
    print()

    print("=== INTERNAL SELFTEST ===")
    self_test()
    print("SELFTEST_OK")
    print()

    print("=== CORE / DATADIR LOCK ===")
    lock_fd = require_core_stopped_and_lock()
    print(f"CORE_DATADIR_LOCK_OK fd={lock_fd}")
    print()

    try:
        print("=== VERIFY FROZEN PROVENANCE ===")
        manifest_sha = verify_sha(
            MANIFEST, MANIFEST_SHA, EXPECTED_MANIFEST_SHA256
        )
        locator_sha = verify_sha(
            LOCATOR, LOCATOR_SHA, EXPECTED_LOCATOR_SHA256
        )
        semantic_sha = verify_sha(
            SEMANTIC_AUDIT,
            SEMANTIC_AUDIT_SHA,
            EXPECTED_SEMANTIC_AUDIT_SHA256,
        )

        stage1_meta = json.loads(
            STAGE1_META.read_text(encoding="utf-8")
        )

        if stage1_meta.get("release_complete") is not True:
            raise RuntimeError("Stage 1 release_complete != true")

        if stage1_meta.get("row_count") != 617699:
            raise RuntimeError("Stage 1 row_count mismatch")

        if (
            stage1_meta.get("locator", {}).get("sha256")
            != EXPECTED_LOCATOR_SHA256
        ):
            raise RuntimeError(
                "Stage 1 meta locator SHA mismatch"
            )

        if (
            stage1_meta.get("xor_dat", {}).get("sha256")
            != EXPECTED_XOR_SHA256
        ):
            raise RuntimeError(
                "Stage 1 meta xor.dat SHA mismatch"
            )

        if (
            stage1_meta.get("script", {}).get("sha256")
            != EXPECTED_STAGE1_SCRIPT_SHA256
        ):
            raise RuntimeError(
                "Stage 1 meta script SHA mismatch"
            )

        semantic_obj = json.loads(
            SEMANTIC_AUDIT.read_text(encoding="utf-8")
        )

        if semantic_obj.get("status") != "GREEN":
            raise RuntimeError(
                "Stage 1 semantic audit status is not GREEN"
            )

        if (
            semantic_obj.get("release_artifacts", {})
            .get("locator_sha256")
            != EXPECTED_LOCATOR_SHA256
        ):
            raise RuntimeError(
                "semantic audit locator SHA mismatch"
            )

        xor_key = XOR_FILE.read_bytes()
        if len(xor_key) != 8:
            raise RuntimeError("xor.dat length mismatch")
        if xor_key.hex() != EXPECTED_XOR_HEX:
            raise RuntimeError("xor.dat key mismatch")
        if sha256_file(XOR_FILE) != EXPECTED_XOR_SHA256:
            raise RuntimeError("xor.dat SHA mismatch")

        print(f"MANIFEST_OK {manifest_sha}")
        print(f"LOCATOR_OK  {locator_sha}")
        print(f"SEMANTIC_OK {semantic_sha}")
        print(f"XOR_OK      {xor_key.hex()}")
        print()

        manifest = load_manifest()
        locator = load_locator(manifest)

        results = []
        total_witness_txs = 0
        total_non_coinbase_witness_txs = 0
        total_txid_wtxid_differences = 0
        valid_commitments = 0

        print("=== RAW BLOCK / TRANSACTION AUDIT ===")

        for height in SAMPLE_HEIGHTS:
            row = locator[height]
            block = read_block(row, xor_key)

            expected_hash = manifest[height]
            expected_prev = (
                "0" * 64 if height == 0 else manifest[height - 1]
            )

            result = parse_block(
                block,
                height,
                expected_hash,
                expected_prev,
            )
            results.append(result)

            total_witness_txs += result["witness_tx_count"]
            total_non_coinbase_witness_txs += (
                result["non_coinbase_witness_tx_count"]
            )
            total_txid_wtxid_differences += (
                result["txid_wtxid_diff_count"]
            )

            if result["witness_commitment"]["present"]:
                valid_commitments += 1

            print(
                f"height={height:6d} "
                f"size={result['block_size']:7d} "
                f"stripped={result['stripped_size']:7d} "
                f"weight={result['weight']:7d} "
                f"txs={result['tx_count']:5d} "
                f"witness_txs={result['witness_tx_count']:5d} "
                f"noncb_wit={result['non_coinbase_witness_tx_count']:5d} "
                f"commitment="
                f"{'YES' if result['witness_commitment']['present'] else 'NO '} "
                f"hash={result['hash']}"
            )

        if results[-1]["hash"] != EXPECTED_END_HASH:
            raise RuntimeError("final sample anchor mismatch")

        # We deliberately require the sample set to exercise actual witness
        # parsing and witness-commitment validation, otherwise this preflight
        # would not test the historical failure mode we care about.
        if total_witness_txs == 0:
            raise RuntimeError(
                "sample set did not exercise any witness transaction"
            )
        if total_non_coinbase_witness_txs == 0:
            raise RuntimeError(
                "sample set did not exercise any non-coinbase "
                "witness transaction"
            )

        if total_txid_wtxid_differences == 0:
            raise RuntimeError(
                "sample set did not exercise txid != wtxid"
            )

        if valid_commitments == 0:
            raise RuntimeError(
                "sample set did not validate any witness commitment"
            )

        print()
        print("============================================")
        print("STAGE 2 DECODER PREFLIGHT: GREEN")
        print("============================================")
        print(f"sample_blocks                  = {len(results)}")
        print(f"witness_transactions           = {total_witness_txs}")
        print(
            f"non_coinbase_witness_txs       = "
            f"{total_non_coinbase_witness_txs}"
        )
        print(
            f"txid_wtxid_differences         = "
            f"{total_txid_wtxid_differences}"
        )
        print(f"valid_witness_commitments      = {valid_commitments}")

    finally:
        os.close(lock_fd)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print()
        print(f"FATAL: {exc}", file=sys.stderr)
        sys.exit(1)
