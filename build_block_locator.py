#!/usr/bin/env python3
# MyBot / UTXO Core v1
# Stage 1 — physical block locator for canonical heights 0..617698.
#
# Reads Bitcoin Core blkNNNNN.dat directly while bitcoind is STOPPED.
# It does NOT parse transactions yet.
#
# Release artifacts:
#   stage/block_locator_0_617698.tsv
#   stage/block_locator_0_617698.tsv.sha256
#   stage/block_files_inventory.tsv
#   stage/block_files_inventory.tsv.sha256
#   stage/block_locator_0_617698.meta.json
#
# Fail-closed properties:
# - Stage 0 canonical manifest and its release metadata are verified.
# - Bitcoin Core must be inactive; its datadir POSIX lock is held for the whole scan.
# - xor.dat key and SHA256 are pinned.
# - blk file set must be contiguous and immutable during the run.
# - every physical record has mainnet magic and a plausible block size.
# - XOR is aligned to absolute byte offset within each file.
# - every canonical block header hash is independently recomputed.
# - every canonical previousblockhash link is checked for ALL heights.
# - every canonical target block must be found exactly once.
# - release artifacts never overwrite existing artifacts.
# - metadata is published last and is the completion marker.

import errno
import fcntl
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

BASE = Path("/opt/mybot_data/etl/utxo_core_v1")
DATADIR = Path("/opt/mybot_data/bitcoin")
BLOCKS_DIR = DATADIR / "blocks"

MANIFEST_DIR = BASE / "manifests"
STAGE_DIR = BASE / "stage"

START_HEIGHT = 0
END_HEIGHT = 617698
EXPECTED_ROWS = END_HEIGHT - START_HEIGHT + 1

MANIFEST = MANIFEST_DIR / f"canonical_chain_{START_HEIGHT}_{END_HEIGHT}.tsv"
MANIFEST_SHA = Path(str(MANIFEST) + ".sha256")
MANIFEST_META = MANIFEST_DIR / f"canonical_chain_{START_HEIGHT}_{END_HEIGHT}.meta.json"

EXPECTED_MANIFEST_SHA256 = (
    "5227507e9b38fbdb63040c1e197cdfb9b39cc2d054c6744722113206c4847161"
)
EXPECTED_GENESIS = (
    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
)
EXPECTED_END_HASH = (
    "000000000000000000095ad21001856998971c4951123d14276b5f13c45e83d8"
)

XOR_FILE = BLOCKS_DIR / "xor.dat"
EXPECTED_XOR_HEX = "2af1c3e24315d54b"
EXPECTED_XOR_SHA256 = (
    "b5e50a9b6a79fce708c9fcfb62a76c512aec637192961c94fd99ffe051b9d6e7"
)

MAINNET_MAGIC = bytes.fromhex("f9beb4d9")
MAX_BLOCK_SERIALIZED_SIZE = 4_000_000
MIN_BLOCK_SERIALIZED_SIZE = 81

LOCATOR = STAGE_DIR / f"block_locator_{START_HEIGHT}_{END_HEIGHT}.tsv"
LOCATOR_SHA = Path(str(LOCATOR) + ".sha256")
INVENTORY = STAGE_DIR / "block_files_inventory.tsv"
INVENTORY_SHA = Path(str(INVENTORY) + ".sha256")
META = STAGE_DIR / f"block_locator_{START_HEIGHT}_{END_HEIGHT}.meta.json"

LOCATOR_TMP = Path(str(LOCATOR) + ".tmp")
LOCATOR_SHA_TMP = Path(str(LOCATOR_SHA) + ".tmp")
INVENTORY_TMP = Path(str(INVENTORY) + ".tmp")
INVENTORY_SHA_TMP = Path(str(INVENTORY_SHA) + ".tmp")
META_TMP = Path(str(META) + ".tmp")

LOCK = STAGE_DIR / f".block_locator_{START_HEIGHT}_{END_HEIGHT}.lock"
CORE_DATADIR_LOCK = DATADIR / ".lock"

EXPECTED_STAGE0_SCRIPT_SHA256 = (
    "67fd5a4e228eb9664fd490b25b08666333d607712c8046bd65583881c88fd580"
)
EXPECTED_STAGE0_CONFIG_SHA256 = (
    "431ee0d1b46976d19030f6870457797571b69f29be00e233ef31bab56b5757b9"
)
EXPECTED_UTXO_REFERENCE_SHA256 = (
    "59df77d53bb30b5835d1bf97c53bd252113f9b9afb3ea200e761519d16b93604"
)

BLK_RE = re.compile(r"^blk([0-9]{5})\.dat$")


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(8 * 1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def valid_hash(value, where):
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(c not in "0123456789abcdef" for c in value)
    ):
        raise RuntimeError(f"INVALID HASH ({where}): {value!r}")
    return value


def sha256d_display(header):
    if len(header) != 80:
        raise ValueError(f"header must be 80 bytes, got {len(header)}")
    return hashlib.sha256(hashlib.sha256(header).digest()).digest()[::-1].hex()


def xor_at(raw, absolute_offset, key):
    if not key:
        raise ValueError("empty XOR key")
    return bytes(
        value ^ key[(absolute_offset + i) % len(key)]
        for i, value in enumerate(raw)
    )


def genesis_header_bytes():
    # Bitcoin mainnet genesis header, serialized in wire order.
    return bytes.fromhex(
        "01000000"
        + "00" * 32
        + "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
        + "29ab5f49"
        + "ffff001d"
        + "1dac2b7c"
    )


def self_test():
    header = genesis_header_bytes()
    if len(header) != 80:
        raise RuntimeError("SELFTEST: genesis header length mismatch")
    if sha256d_display(header) != EXPECTED_GENESIS:
        raise RuntimeError("SELFTEST: genesis SHA256d mismatch")

    key = bytes.fromhex(EXPECTED_XOR_HEX)
    plain = (
        MAINNET_MAGIC
        + struct.pack("<I", 285)
        + header
        + bytes(205)
    )
    encoded = xor_at(plain, 0, key)
    decoded = xor_at(encoded, 0, key)

    if decoded != plain:
        raise RuntimeError("SELFTEST: XOR roundtrip mismatch")
    if decoded[:4] != MAINNET_MAGIC:
        raise RuntimeError("SELFTEST: magic mismatch")
    if struct.unpack("<I", decoded[4:8])[0] != 285:
        raise RuntimeError("SELFTEST: size mismatch")
    if sha256d_display(decoded[8:88]) != EXPECTED_GENESIS:
        raise RuntimeError("SELFTEST: decoded genesis mismatch")

    # Absolute-offset alignment must also roundtrip at a non-zero offset.
    offset = 12345
    probe = bytes(range(251))
    if xor_at(xor_at(probe, offset, key), offset, key) != probe:
        raise RuntimeError("SELFTEST: offset XOR roundtrip mismatch")


def require_core_stopped():
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
            "BITCOIN CORE SYSTEMD SERVICE MUST BE STOPPED\n"
            f"systemctl is-active bitcoind -> {state!r}"
        )

    # A manually started bitcoind would not necessarily make the systemd
    # unit active. Refuse that case too.
    pgrep = subprocess.run(
        ["pgrep", "-x", "bitcoind"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if pgrep.returncode == 0:
        pids = " ".join(pgrep.stdout.split())
        raise RuntimeError(
            "BITCOIND PROCESS STILL EXISTS OUTSIDE/BEYOND SYSTEMD\n"
            f"pids={pids}"
        )
    if pgrep.returncode not in (1,):
        raise RuntimeError(
            f"PGREP FAILED: returncode={pgrep.returncode}"
        )

    return state


def acquire_core_datadir_lock():
    """Acquire the same POSIX record-lock region Bitcoin Core uses on datadir/.lock.

    Linux Bitcoin Core opens DATADIR/.lock O_RDWR and uses fcntl(F_SETLK)
    with F_WRLCK, SEEK_SET, start=0, len=0. Python lockf() is a wrapper
    around the fcntl record-locking API, so holding this descriptor prevents
    Bitcoin Core from acquiring its datadir lock while Stage 1 is running.
    """
    if not CORE_DATADIR_LOCK.is_file():
        raise RuntimeError(
            f"BITCOIN CORE DATADIR LOCK FILE MISSING: {CORE_DATADIR_LOCK}"
        )

    fd = os.open(CORE_DATADIR_LOCK, os.O_RDWR)
    try:
        fcntl.lockf(
            fd,
            fcntl.LOCK_EX | fcntl.LOCK_NB,
            0,
            0,
            os.SEEK_SET,
        )
    except OSError as exc:
        os.close(fd)
        if exc.errno in (errno.EACCES, errno.EAGAIN):
            raise RuntimeError(
                "BITCOIN CORE DATADIR LOCK IS BUSY; "
                "ANOTHER CORE PROCESS MAY BE USING THIS DATADIR"
            ) from exc
        raise

    return fd


def check_release_paths():
    finals = [LOCATOR, LOCATOR_SHA, INVENTORY, INVENTORY_SHA, META]
    existing = [p for p in finals if p.exists()]
    if existing:
        raise RuntimeError(
            "REFUSE OVERWRITE: STAGE 1 RELEASE ARTIFACT(S) EXIST\n"
            + "\n".join(f"  - {p}" for p in existing)
        )

    temps = [
        LOCATOR_TMP,
        LOCATOR_SHA_TMP,
        INVENTORY_TMP,
        INVENTORY_SHA_TMP,
        META_TMP,
    ]
    stale = [p for p in temps if p.exists()]
    if stale:
        raise RuntimeError(
            "STALE TEMP ARTIFACT(S) EXIST; INSPECT/REMOVE EXPLICITLY\n"
            + "\n".join(f"  - {p}" for p in stale)
        )


def validate_stage0():
    for path in (MANIFEST, MANIFEST_SHA, MANIFEST_META):
        if not path.is_file():
            raise RuntimeError(f"MISSING STAGE 0 ARTIFACT: {path}")

    actual_sha = sha256_file(MANIFEST)
    if actual_sha != EXPECTED_MANIFEST_SHA256:
        raise RuntimeError(
            "CANONICAL MANIFEST SHA256 MISMATCH\n"
            f"expected={EXPECTED_MANIFEST_SHA256}\n"
            f"actual  ={actual_sha}"
        )

    sidecar = MANIFEST_SHA.read_text(encoding="utf-8").strip().split()
    if not sidecar or sidecar[0].lower() != actual_sha:
        raise RuntimeError("CANONICAL MANIFEST SHA SIDECAR MISMATCH")

    try:
        meta = json.loads(MANIFEST_META.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError(f"INVALID STAGE 0 META JSON: {exc}") from exc

    if meta.get("release_complete") is not True:
        raise RuntimeError("STAGE 0 META: release_complete != true")
    if meta.get("row_count") != EXPECTED_ROWS:
        raise RuntimeError(
            f"STAGE 0 META ROW COUNT: {meta.get('row_count')} != {EXPECTED_ROWS}"
        )
    if meta.get("manifest_sha256") != actual_sha:
        raise RuntimeError("STAGE 0 META MANIFEST SHA MISMATCH")
    if meta.get("end_hash") != EXPECTED_END_HASH:
        raise RuntimeError("STAGE 0 META END HASH MISMATCH")

    stage0_script = meta.get("script")
    if not isinstance(stage0_script, dict):
        raise RuntimeError("STAGE 0 META SCRIPT PROVENANCE MISSING")
    if stage0_script.get("sha256") != EXPECTED_STAGE0_SCRIPT_SHA256:
        raise RuntimeError("STAGE 0 META SCRIPT SHA256 MISMATCH")

    source_files = meta.get("source_files")
    if not isinstance(source_files, dict):
        raise RuntimeError("STAGE 0 META SOURCE FILE PROVENANCE MISSING")

    source_xor = source_files.get("xor_dat")
    if not isinstance(source_xor, dict):
        raise RuntimeError("STAGE 0 META XOR PROVENANCE MISSING")
    if source_xor.get("hex") != EXPECTED_XOR_HEX:
        raise RuntimeError("STAGE 0 META XOR HEX MISMATCH")
    if source_xor.get("sha256") != EXPECTED_XOR_SHA256:
        raise RuntimeError("STAGE 0 META XOR SHA256 MISMATCH")

    source_conf = source_files.get("bitcoin_conf")
    if not isinstance(source_conf, dict):
        raise RuntimeError("STAGE 0 META BITCOIN.CONF PROVENANCE MISSING")
    if source_conf.get("sha256") != EXPECTED_STAGE0_CONFIG_SHA256:
        raise RuntimeError("STAGE 0 META BITCOIN.CONF SHA256 MISMATCH")

    reference = meta.get("utxo_reference")
    if not isinstance(reference, dict):
        raise RuntimeError("STAGE 0 META UTXO REFERENCE PROVENANCE MISSING")
    if reference.get("sha256") != EXPECTED_UTXO_REFERENCE_SHA256:
        raise RuntimeError("STAGE 0 META UTXO REFERENCE SHA256 MISMATCH")
    if reference.get("height") != END_HEIGHT:
        raise RuntimeError("STAGE 0 META UTXO REFERENCE HEIGHT MISMATCH")
    if reference.get("bestblock") != EXPECTED_END_HASH:
        raise RuntimeError("STAGE 0 META UTXO REFERENCE BESTBLOCK MISMATCH")

    ordered_hashes = []
    hash_to_height = {}

    with open(MANIFEST, "r", encoding="ascii") as f:
        header = f.readline().rstrip("\n")
        if header != "height\tblock_hash":
            raise RuntimeError(f"BAD STAGE 0 HEADER: {header!r}")

        expected_height = START_HEIGHT
        for line_no, line in enumerate(f, start=2):
            parts = line.rstrip("\n").split("\t")
            if len(parts) != 2:
                raise RuntimeError(
                    f"MALFORMED STAGE 0 LINE {line_no}: {line!r}"
                )

            try:
                height = int(parts[0])
            except ValueError as exc:
                raise RuntimeError(
                    f"BAD HEIGHT AT STAGE 0 LINE {line_no}: {parts[0]!r}"
                ) from exc

            if height != expected_height:
                raise RuntimeError(
                    "STAGE 0 HEIGHT GAP/ORDER ERROR: "
                    f"expected={expected_height} actual={height}"
                )

            block_hash = valid_hash(
                parts[1], f"stage0 height={height}"
            )

            if block_hash in hash_to_height:
                raise RuntimeError(
                    f"STAGE 0 DUPLICATE BLOCK HASH: {block_hash}"
                )

            ordered_hashes.append(block_hash)
            hash_to_height[block_hash] = height
            expected_height += 1

    if len(ordered_hashes) != EXPECTED_ROWS:
        raise RuntimeError(
            f"STAGE 0 ROW COUNT: {len(ordered_hashes)} != {EXPECTED_ROWS}"
        )
    if ordered_hashes[0] != EXPECTED_GENESIS:
        raise RuntimeError("STAGE 0 GENESIS MISMATCH")
    if ordered_hashes[-1] != EXPECTED_END_HASH:
        raise RuntimeError("STAGE 0 END HASH MISMATCH")

    return {
        "manifest_sha256": actual_sha,
        "meta_sha256": sha256_file(MANIFEST_META),
        "ordered_hashes": ordered_hashes,
        "hash_to_height": hash_to_height,
    }


def validate_xor():
    if not XOR_FILE.is_file():
        raise RuntimeError(f"MISSING XOR FILE: {XOR_FILE}")

    key = XOR_FILE.read_bytes()
    if len(key) != 8:
        raise RuntimeError(
            f"XOR KEY LENGTH MISMATCH: {len(key)} != 8"
        )

    actual_hex = key.hex()
    if actual_hex != EXPECTED_XOR_HEX:
        raise RuntimeError(
            "XOR KEY MISMATCH\n"
            f"expected={EXPECTED_XOR_HEX}\nactual  ={actual_hex}"
        )

    actual_sha = sha256_file(XOR_FILE)
    if actual_sha != EXPECTED_XOR_SHA256:
        raise RuntimeError(
            "XOR.DAT SHA256 MISMATCH\n"
            f"expected={EXPECTED_XOR_SHA256}\nactual  ={actual_sha}"
        )

    return {
        "key": key,
        "hex": actual_hex,
        "sha256": actual_sha,
    }


def snapshot_block_files():
    entries = []

    for path in BLOCKS_DIR.iterdir():
        if not path.is_file():
            continue
        match = BLK_RE.match(path.name)
        if not match:
            continue

        number = int(match.group(1))
        st = path.stat()
        entries.append({
            "file_number": number,
            "name": path.name,
            "path": path,
            "size_bytes": st.st_size,
            "mtime_ns": st.st_mtime_ns,
            "ctime_ns": st.st_ctime_ns,
            "inode": st.st_ino,
            "device": st.st_dev,
        })

    entries.sort(key=lambda x: x["file_number"])

    if not entries:
        raise RuntimeError(f"NO blkNNNNN.dat FILES IN {BLOCKS_DIR}")

    if entries[0]["file_number"] != 0:
        raise RuntimeError(
            f"FIRST BLOCK FILE IS {entries[0]['name']}, EXPECTED blk00000.dat"
        )

    for expected, entry in enumerate(entries):
        if entry["file_number"] != expected:
            raise RuntimeError(
                "BLOCK FILE NUMBER GAP/ORDER ERROR: "
                f"expected=blk{expected:05d}.dat actual={entry['name']}"
            )

    for entry in entries:
        if entry["size_bytes"] <= 0:
            raise RuntimeError(
                f"EMPTY BLOCK FILE: {entry['path']}"
            )

    return entries


def verify_zero_tail(fd, path, start, file_size):
    remaining = file_size - start
    if remaining < 0:
        raise RuntimeError(
            f"NEGATIVE TAIL LENGTH: {path} start={start} size={file_size}"
        )

    pos = start
    chunk_size = 8 * 1024 * 1024

    while pos < file_size:
        want = min(chunk_size, file_size - pos)
        data = os.pread(fd, want, pos)
        if len(data) != want:
            raise RuntimeError(
                f"SHORT READ WHILE VERIFYING ZERO TAIL: {path} "
                f"offset={pos} want={want} got={len(data)}"
            )
        if any(data):
            first_nonzero = next(i for i, b in enumerate(data) if b)
            raise RuntimeError(
                f"NONZERO BYTES AFTER RECORD AREA: {path} "
                f"offset={pos + first_nonzero}"
            )
        pos += want

    return remaining


def scan_files(entries, stage0, xor_info):
    ordered_hashes = stage0["ordered_hashes"]
    hash_to_height = stage0["hash_to_height"]
    key = xor_info["key"]

    found = {}
    per_file = []

    total_records = 0
    canonical_records = 0
    noncanonical_records = 0
    total_padding = 0
    started = time.time()

    print(
        f"source files : {len(entries)} "
        f"(blk{entries[0]['file_number']:05d}.."
        f"blk{entries[-1]['file_number']:05d})"
    )
    print(
        f"source bytes : "
        f"{sum(e['size_bytes'] for e in entries):,}"
    )
    print()

    for file_index, entry in enumerate(entries, start=1):
        path = entry["path"]
        file_size = entry["size_bytes"]
        file_records = 0
        file_canonical = 0
        file_noncanonical = 0
        padding_bytes = 0
        pos = 0

        fd = os.open(path, os.O_RDONLY)
        try:
            while pos < file_size:
                remaining = file_size - pos

                if remaining < 8:
                    tail = os.pread(fd, remaining, pos)
                    if len(tail) != remaining:
                        raise RuntimeError(
                            f"SHORT FINAL TAIL READ: {path} "
                            f"offset={pos} want={remaining} got={len(tail)}"
                        )
                    if any(tail):
                        raise RuntimeError(
                            f"NONZERO SHORT TAIL: {path} offset={pos} "
                            f"bytes={tail.hex()}"
                        )
                    padding_bytes += remaining
                    pos = file_size
                    break

                raw8 = os.pread(fd, 8, pos)
                if len(raw8) != 8:
                    raise RuntimeError(
                        f"SHORT STORAGE HEADER READ: {path} "
                        f"offset={pos} got={len(raw8)}"
                    )

                # Unwritten preallocation is raw zero bytes, not XOR-obfuscated.
                if raw8 == b"\x00" * 8:
                    padding_bytes += verify_zero_tail(
                        fd, path, pos, file_size
                    )
                    pos = file_size
                    break

                decoded8 = xor_at(raw8, pos, key)
                magic = decoded8[:4]

                if magic != MAINNET_MAGIC:
                    raise RuntimeError(
                        "MAINNET MAGIC MISMATCH\n"
                        f"file={path}\n"
                        f"record_offset={pos}\n"
                        f"raw8={raw8.hex()}\n"
                        f"decoded8={decoded8.hex()}\n"
                        f"expected_magic={MAINNET_MAGIC.hex()}\n"
                        f"actual_magic={magic.hex()}"
                    )

                block_size = struct.unpack("<I", decoded8[4:8])[0]

                if not (
                    MIN_BLOCK_SERIALIZED_SIZE
                    <= block_size
                    <= MAX_BLOCK_SERIALIZED_SIZE
                ):
                    raise RuntimeError(
                        "IMPLAUSIBLE BLOCK SIZE\n"
                        f"file={path}\n"
                        f"record_offset={pos}\n"
                        f"block_size={block_size}"
                    )

                record_end = pos + 8 + block_size
                if record_end > file_size:
                    raise RuntimeError(
                        "BLOCK RECORD EXTENDS PAST FILE\n"
                        f"file={path}\n"
                        f"record_offset={pos}\n"
                        f"block_size={block_size}\n"
                        f"record_end={record_end}\n"
                        f"file_size={file_size}"
                    )

                raw_header = os.pread(fd, 80, pos + 8)
                if len(raw_header) != 80:
                    raise RuntimeError(
                        f"SHORT BLOCK HEADER READ: {path} "
                        f"offset={pos + 8} got={len(raw_header)}"
                    )

                header = xor_at(raw_header, pos + 8, key)
                block_hash = sha256d_display(header)

                file_records += 1
                total_records += 1

                height = hash_to_height.get(block_hash)

                if height is None:
                    file_noncanonical += 1
                    noncanonical_records += 1
                else:
                    prev_hash = header[4:36][::-1].hex()
                    expected_prev = (
                        "0" * 64
                        if height == 0
                        else ordered_hashes[height - 1]
                    )

                    if prev_hash != expected_prev:
                        raise RuntimeError(
                            "CANONICAL PREVHASH LINK MISMATCH\n"
                            f"height={height}\n"
                            f"hash={block_hash}\n"
                            f"file={path}\n"
                            f"record_offset={pos}\n"
                            f"expected_prev={expected_prev}\n"
                            f"actual_prev  ={prev_hash}"
                        )

                    if height in found:
                        old = found[height]
                        raise RuntimeError(
                            "DUPLICATE PHYSICAL CANONICAL BLOCK\n"
                            f"height={height}\n"
                            f"hash={block_hash}\n"
                            f"first={old['blk_file']}@{old['record_offset']}\n"
                            f"again={path.name}@{pos}"
                        )

                    found[height] = {
                        "height": height,
                        "block_hash": block_hash,
                        "prev_hash": prev_hash,
                        "blk_file": path.name,
                        "file_number": entry["file_number"],
                        "record_offset": pos,
                        "block_offset": pos + 8,
                        "block_size": block_size,
                        "record_size": block_size + 8,
                    }

                    file_canonical += 1
                    canonical_records += 1

                pos = record_end

        finally:
            os.close(fd)

        total_padding += padding_bytes

        per_file.append({
            "file_number": entry["file_number"],
            "blk_file": entry["name"],
            "size_bytes": file_size,
            "mtime_ns": entry["mtime_ns"],
            "ctime_ns": entry["ctime_ns"],
            "inode": entry["inode"],
            "device": entry["device"],
            "record_count": file_records,
            "canonical_matches": file_canonical,
            "noncanonical_records": file_noncanonical,
            "padding_bytes": padding_bytes,
        })

        if (
            file_index == 1
            or file_index % 100 == 0
            or file_index == len(entries)
        ):
            elapsed = time.time() - started
            remaining_targets = EXPECTED_ROWS - len(found)
            print(
                f"file={entry['name']}  "
                f"files={file_index}/{len(entries)}  "
                f"records={total_records:,}  "
                f"canonical={len(found):,}/{EXPECTED_ROWS:,}  "
                f"remaining={remaining_targets:,}  "
                f"noncanonical={noncanonical_records:,}  "
                f"elapsed={elapsed:.1f}s",
                flush=True,
            )

    missing = [
        h for h in range(START_HEIGHT, END_HEIGHT + 1)
        if h not in found
    ]

    if missing:
        preview = missing[:50]
        raise RuntimeError(
            f"MISSING CANONICAL BLOCKS: {len(missing)}\n"
            f"first_missing={preview}"
        )

    if len(found) != EXPECTED_ROWS:
        raise RuntimeError(
            f"CANONICAL FOUND COUNT MISMATCH: "
            f"{len(found)} != {EXPECTED_ROWS}"
        )

    return {
        "found": found,
        "per_file": per_file,
        "total_records": total_records,
        "canonical_records": canonical_records,
        "noncanonical_records": noncanonical_records,
        "padding_bytes": total_padding,
        "elapsed_seconds": time.time() - started,
    }


def verify_source_unchanged(entries):
    current = snapshot_block_files()

    if len(current) != len(entries):
        raise RuntimeError(
            "BLOCK FILE SET CHANGED DURING SCAN: "
            f"before={len(entries)} after={len(current)}"
        )

    for before, after in zip(entries, current):
        keys = (
            "file_number",
            "name",
            "size_bytes",
            "mtime_ns",
            "ctime_ns",
            "inode",
            "device",
        )
        for key in keys:
            if before[key] != after[key]:
                raise RuntimeError(
                    "BLOCK SOURCE CHANGED DURING SCAN\n"
                    f"file={before['name']}\n"
                    f"field={key}\n"
                    f"before={before[key]!r}\n"
                    f"after ={after[key]!r}"
                )

    require_core_stopped()


def write_locator_tmp(stage0, scan):
    found = scan["found"]
    ordered_hashes = stage0["ordered_hashes"]

    with open(
        LOCATOR_TMP, "x", encoding="ascii", buffering=1024 * 1024
    ) as f:
        f.write(
            "height\tblock_hash\tprev_hash\tblk_file\tfile_number\t"
            "record_offset\tblock_offset\tblock_size\trecord_size\n"
        )

        for height in range(START_HEIGHT, END_HEIGHT + 1):
            row = found[height]

            if row["block_hash"] != ordered_hashes[height]:
                raise RuntimeError(
                    f"IN-MEMORY LOCATOR HASH MISMATCH AT {height}"
                )

            f.write(
                f"{height}\t"
                f"{row['block_hash']}\t"
                f"{row['prev_hash']}\t"
                f"{row['blk_file']}\t"
                f"{row['file_number']}\t"
                f"{row['record_offset']}\t"
                f"{row['block_offset']}\t"
                f"{row['block_size']}\t"
                f"{row['record_size']}\n"
            )

        f.flush()
        os.fsync(f.fileno())


def write_inventory_tmp(scan):
    with open(
        INVENTORY_TMP, "x", encoding="ascii", buffering=1024 * 1024
    ) as f:
        f.write(
            "file_number\tblk_file\tsize_bytes\tmtime_ns\tctime_ns\tinode\tdevice\t"
            "record_count\tcanonical_matches\tnoncanonical_records\t"
            "padding_bytes\n"
        )

        for row in scan["per_file"]:
            f.write(
                f"{row['file_number']}\t"
                f"{row['blk_file']}\t"
                f"{row['size_bytes']}\t"
                f"{row['mtime_ns']}\t"
                f"{row['ctime_ns']}\t"
                f"{row['inode']}\t"
                f"{row['device']}\t"
                f"{row['record_count']}\t"
                f"{row['canonical_matches']}\t"
                f"{row['noncanonical_records']}\t"
                f"{row['padding_bytes']}\n"
            )

        f.flush()
        os.fsync(f.fileno())


def validate_locator_tmp(stage0):
    ordered_hashes = stage0["ordered_hashes"]
    rows = 0
    locations = set()

    with open(LOCATOR_TMP, "r", encoding="ascii") as f:
        header = f.readline().rstrip("\n")
        expected_header = (
            "height\tblock_hash\tprev_hash\tblk_file\tfile_number\t"
            "record_offset\tblock_offset\tblock_size\trecord_size"
        )
        if header != expected_header:
            raise RuntimeError(f"BAD LOCATOR HEADER: {header!r}")

        for expected_height, line in enumerate(f, start=START_HEIGHT):
            parts = line.rstrip("\n").split("\t")
            if len(parts) != 9:
                raise RuntimeError(
                    f"BAD LOCATOR COLUMN COUNT AT HEIGHT {expected_height}: "
                    f"{len(parts)}"
                )

            (
                height_s,
                block_hash,
                prev_hash,
                blk_file,
                file_number_s,
                record_offset_s,
                block_offset_s,
                block_size_s,
                record_size_s,
            ) = parts

            height = int(height_s)
            file_number = int(file_number_s)
            record_offset = int(record_offset_s)
            block_offset = int(block_offset_s)
            block_size = int(block_size_s)
            record_size = int(record_size_s)

            if height != expected_height:
                raise RuntimeError(
                    f"LOCATOR HEIGHT ERROR: "
                    f"expected={expected_height} actual={height}"
                )

            valid_hash(block_hash, f"locator height={height}")
            valid_hash(prev_hash, f"locator prev height={height}")

            if block_hash != ordered_hashes[height]:
                raise RuntimeError(
                    f"LOCATOR/MANIFEST HASH MISMATCH AT HEIGHT {height}"
                )

            expected_prev = (
                "0" * 64 if height == 0 else ordered_hashes[height - 1]
            )
            if prev_hash != expected_prev:
                raise RuntimeError(
                    f"LOCATOR PREVHASH MISMATCH AT HEIGHT {height}"
                )

            expected_name = f"blk{file_number:05d}.dat"
            if blk_file != expected_name:
                raise RuntimeError(
                    f"LOCATOR FILE NAME/NUMBER MISMATCH AT HEIGHT {height}"
                )

            if record_offset < 0:
                raise RuntimeError(
                    f"NEGATIVE RECORD OFFSET AT HEIGHT {height}"
                )
            if block_offset != record_offset + 8:
                raise RuntimeError(
                    f"BLOCK OFFSET ERROR AT HEIGHT {height}"
                )
            if not (
                MIN_BLOCK_SERIALIZED_SIZE
                <= block_size
                <= MAX_BLOCK_SERIALIZED_SIZE
            ):
                raise RuntimeError(
                    f"BLOCK SIZE ERROR AT HEIGHT {height}: {block_size}"
                )
            if record_size != block_size + 8:
                raise RuntimeError(
                    f"RECORD SIZE ERROR AT HEIGHT {height}"
                )

            location = (file_number, record_offset)
            if location in locations:
                raise RuntimeError(
                    f"DUPLICATE PHYSICAL LOCATION IN LOCATOR: {location}"
                )
            locations.add(location)

            rows += 1

    if rows != EXPECTED_ROWS:
        raise RuntimeError(
            f"LOCATOR ROW COUNT: {rows} != {EXPECTED_ROWS}"
        )

    return {
        "row_count": rows,
        "unique_locations": len(locations),
    }


def validate_inventory_tmp(entries, scan):
    rows = 0
    summed_records = 0
    summed_canonical = 0
    summed_noncanonical = 0
    summed_padding = 0

    with open(INVENTORY_TMP, "r", encoding="ascii") as f:
        header = f.readline().rstrip("\n")
        expected_header = (
            "file_number\tblk_file\tsize_bytes\tmtime_ns\tctime_ns\tinode\tdevice\t"
            "record_count\tcanonical_matches\tnoncanonical_records\t"
            "padding_bytes"
        )
        if header != expected_header:
            raise RuntimeError(f"BAD INVENTORY HEADER: {header!r}")

        for expected_entry, line in zip(entries, f):
            parts = line.rstrip("\n").split("\t")
            if len(parts) != 11:
                raise RuntimeError(
                    f"BAD INVENTORY COLUMN COUNT: {len(parts)}"
                )

            (
                file_number_s,
                blk_file,
                size_s,
                mtime_s,
                ctime_s,
                inode_s,
                device_s,
                records_s,
                canonical_s,
                noncanonical_s,
                padding_s,
            ) = parts

            if int(file_number_s) != expected_entry["file_number"]:
                raise RuntimeError("INVENTORY FILE NUMBER MISMATCH")
            if blk_file != expected_entry["name"]:
                raise RuntimeError("INVENTORY FILE NAME MISMATCH")
            if int(size_s) != expected_entry["size_bytes"]:
                raise RuntimeError("INVENTORY SIZE MISMATCH")
            if int(mtime_s) != expected_entry["mtime_ns"]:
                raise RuntimeError("INVENTORY MTIME MISMATCH")
            if int(ctime_s) != expected_entry["ctime_ns"]:
                raise RuntimeError("INVENTORY CTIME MISMATCH")
            if int(inode_s) != expected_entry["inode"]:
                raise RuntimeError("INVENTORY INODE MISMATCH")
            if int(device_s) != expected_entry["device"]:
                raise RuntimeError("INVENTORY DEVICE MISMATCH")

            summed_records += int(records_s)
            summed_canonical += int(canonical_s)
            summed_noncanonical += int(noncanonical_s)
            summed_padding += int(padding_s)
            rows += 1

        extra = f.readline()
        if extra:
            raise RuntimeError("EXTRA INVENTORY ROWS")

    if rows != len(entries):
        raise RuntimeError(
            f"INVENTORY ROW COUNT: {rows} != {len(entries)}"
        )
    if summed_records != scan["total_records"]:
        raise RuntimeError("INVENTORY TOTAL RECORD COUNT MISMATCH")
    if summed_canonical != scan["canonical_records"]:
        raise RuntimeError("INVENTORY CANONICAL COUNT MISMATCH")
    if summed_noncanonical != scan["noncanonical_records"]:
        raise RuntimeError("INVENTORY NONCANONICAL COUNT MISMATCH")
    if summed_padding != scan["padding_bytes"]:
        raise RuntimeError("INVENTORY PADDING COUNT MISMATCH")

    return {
        "row_count": rows,
        "record_count": summed_records,
        "canonical_records": summed_canonical,
        "noncanonical_records": summed_noncanonical,
        "padding_bytes": summed_padding,
    }


def publish(stage0, xor_info, entries, scan, locator_check, inventory_check):
    locator_sha = sha256_file(LOCATOR_TMP)
    inventory_sha = sha256_file(INVENTORY_TMP)
    script_path = Path(__file__).resolve()
    script_sha = sha256_file(script_path)

    # One last immutability check before release publication.
    verify_source_unchanged(entries)

    meta = {
        "schema": "mybot_block_locator_v1_1",
        "release_complete": True,
        "created_utc": utc_now(),
        "start_height": START_HEIGHT,
        "end_height": END_HEIGHT,
        "row_count": locator_check["row_count"],
        "canonical_manifest": {
            "path": str(MANIFEST),
            "sha256": stage0["manifest_sha256"],
            "meta_sha256": stage0["meta_sha256"],
        },
        "xor_dat": {
            "path": str(XOR_FILE),
            "hex": xor_info["hex"],
            "sha256": xor_info["sha256"],
        },
        "block_source": {
            "directory": str(BLOCKS_DIR),
            "file_count": len(entries),
            "first_file": entries[0]["name"],
            "last_file": entries[-1]["name"],
            "total_size_bytes": sum(e["size_bytes"] for e in entries),
            "source_restat_unchanged_during_scan": True,
            "bitcoin_core_service_state": "inactive",
            "bitcoin_core_process_check": "no-bitcoind",
            "datadir_posix_lock_held_during_scan": True,
        },
        "scan": {
            "physical_records": scan["total_records"],
            "canonical_records": scan["canonical_records"],
            "noncanonical_records": scan["noncanonical_records"],
            "missing_canonical": 0,
            "duplicate_canonical": 0,
            "all_canonical_prevhash_links_valid": True,
            "padding_bytes": scan["padding_bytes"],
            "elapsed_seconds": round(scan["elapsed_seconds"], 6),
        },
        "locator": {
            "file": LOCATOR.name,
            "sha256": locator_sha,
            "row_count": locator_check["row_count"],
            "unique_physical_locations": locator_check["unique_locations"],
        },
        "inventory": {
            "file": INVENTORY.name,
            "sha256": inventory_sha,
            "row_count": inventory_check["row_count"],
        },
        "script": {
            "path": str(script_path),
            "sha256": script_sha,
        },
        "validation": {
            "mainnet_magic_all_records": True,
            "block_sizes_plausible_all_records": True,
            "canonical_header_sha256d_all": True,
            "canonical_prevhash_links_all": True,
            "canonical_found_exactly_once": True,
            "source_restat_unchanged": True,
            "datadir_posix_lock_held": True,
        },
    }

    with open(LOCATOR_SHA_TMP, "x", encoding="ascii") as f:
        f.write(f"{locator_sha}  {LOCATOR.name}\n")
        f.flush()
        os.fsync(f.fileno())

    with open(INVENTORY_SHA_TMP, "x", encoding="ascii") as f:
        f.write(f"{inventory_sha}  {INVENTORY.name}\n")
        f.flush()
        os.fsync(f.fileno())

    with open(META_TMP, "x", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, sort_keys=True)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())

    # Publish primary data first.
    os.replace(LOCATOR_TMP, LOCATOR)
    os.replace(INVENTORY_TMP, INVENTORY)
    fsync_dir(STAGE_DIR)

    if sha256_file(LOCATOR) != locator_sha:
        raise RuntimeError("POST-PUBLISH LOCATOR SHA256 MISMATCH")
    if sha256_file(INVENTORY) != inventory_sha:
        raise RuntimeError("POST-PUBLISH INVENTORY SHA256 MISMATCH")

    # Publish checksum sidecars next.
    os.replace(LOCATOR_SHA_TMP, LOCATOR_SHA)
    os.replace(INVENTORY_SHA_TMP, INVENTORY_SHA)
    fsync_dir(STAGE_DIR)

    # Metadata is the final completion marker.
    os.replace(META_TMP, META)
    fsync_dir(STAGE_DIR)

    return {
        "locator_sha256": locator_sha,
        "inventory_sha256": inventory_sha,
        "script_sha256": script_sha,
    }


def main():
    os.umask(0o027)
    STAGE_DIR.mkdir(parents=True, exist_ok=True)

    lock = open(LOCK, "a+", encoding="ascii")
    try:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        raise RuntimeError(
            f"ANOTHER STAGE 1 LOCATOR IS RUNNING: {LOCK}"
        ) from exc

    print("=== MYBOT STAGE 1 BLOCK LOCATOR v1.1 ===")
    print(f"target      : {START_HEIGHT}..{END_HEIGHT}")
    print(f"target rows : {EXPECTED_ROWS}")
    print(f"blocks dir  : {BLOCKS_DIR}")
    print(f"stage dir   : {STAGE_DIR}")
    print()

    print("=== INTERNAL SELFTEST ===")
    self_test()
    print("SELFTEST_OK")
    print()

    print("=== CORE STATE ===")
    state = require_core_stopped()
    print(f"CORE_OK state={state}")
    print()

    print("=== ACQUIRE BITCOIN CORE DATADIR LOCK ===")
    core_lock_fd = acquire_core_datadir_lock()
    print(f"CORE_DATADIR_LOCK_OK path={CORE_DATADIR_LOCK} fd={core_lock_fd}")
    print()

    # Re-check after locking to close the stop/check/lock race window.
    require_core_stopped()

    print("=== RELEASE PATH PREFLIGHT ===")
    check_release_paths()
    print("OUTPUT_PATHS_OK")
    print()

    print("=== VERIFY STAGE 0 ===")
    stage0 = validate_stage0()
    print(
        f"STAGE0_OK rows={len(stage0['ordered_hashes'])} "
        f"sha256={stage0['manifest_sha256']}"
    )
    print()

    print("=== VERIFY XOR.DAT ===")
    xor_info = validate_xor()
    print(
        f"XOR_OK hex={xor_info['hex']} "
        f"sha256={xor_info['sha256']}"
    )
    print()

    print("=== SNAPSHOT BLOCK SOURCE ===")
    entries = snapshot_block_files()
    print(
        f"SOURCE_OK files={len(entries)} "
        f"first={entries[0]['name']} "
        f"last={entries[-1]['name']} "
        f"bytes={sum(e['size_bytes'] for e in entries):,}"
    )
    print()

    print("=== SCAN PHYSICAL BLOCK RECORDS ===")
    scan = scan_files(entries, stage0, xor_info)
    print()
    print(
        f"SCAN_OK physical_records={scan['total_records']:,} "
        f"canonical={scan['canonical_records']:,} "
        f"noncanonical={scan['noncanonical_records']:,} "
        f"padding_bytes={scan['padding_bytes']:,}"
    )
    print()

    print("=== VERIFY SOURCE IMMUTABILITY ===")
    verify_source_unchanged(entries)
    print("SOURCE_UNCHANGED_OK")
    print()

    print("=== WRITE RELEASE TEMPS ===")
    write_locator_tmp(stage0, scan)
    write_inventory_tmp(scan)
    print("TEMP_WRITE_OK")
    print()

    print("=== FULL LOCATOR VALIDATION ===")
    locator_check = validate_locator_tmp(stage0)
    print(
        f"LOCATOR_OK rows={locator_check['row_count']} "
        f"unique_locations={locator_check['unique_locations']}"
    )
    print()

    print("=== FULL INVENTORY VALIDATION ===")
    inventory_check = validate_inventory_tmp(entries, scan)
    print(
        f"INVENTORY_OK files={inventory_check['row_count']} "
        f"records={inventory_check['record_count']:,}"
    )
    print()

    print("=== PUBLISH STAGE 1 RELEASE ===")
    released = publish(
        stage0,
        xor_info,
        entries,
        scan,
        locator_check,
        inventory_check,
    )

    print()
    print("==================================================")
    print("STAGE 1 BLOCK LOCATOR RELEASE COMPLETE")
    print("==================================================")
    print(f"canonical rows = {locator_check['row_count']}")
    print(f"physical recs  = {scan['total_records']}")
    print(f"noncanonical   = {scan['noncanonical_records']}")
    print(f"padding bytes  = {scan['padding_bytes']}")
    print(f"locator sha256 = {released['locator_sha256']}")
    print(f"inventory sha  = {released['inventory_sha256']}")
    print(f"script sha256  = {released['script_sha256']}")
    print(f"locator        = {LOCATOR}")
    print(f"inventory      = {INVENTORY}")
    print(f"meta           = {META}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print()
        print(f"FATAL: {exc}", file=sys.stderr)
        sys.exit(1)
