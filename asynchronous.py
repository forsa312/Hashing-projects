#!/usr/bin/env python3
# =============================================================================
#   CBI INDUSTRIES // INTERNAL SYSTEM UTILITY
#   Project: Avalanche Hash Processing Tool (Async / Multi-Directory)
#   Division: Beacon Computing Initiative (CBI)
#   Build Year: 2025
#   Classification: Operational / Controlled
#   Contact: systems@cbi-industries.local
#
#   Description:
#   Concurrent hashing and avalanche-mix processing for file trees. Intended
#   for integrity assurance, verification workflows, and cryptographic
#   one-way derivation of file states. Use with caution in overwrite mode.
#
# =============================================================================

from __future__ import annotations
import hashlib, hmac, secrets, json, os, sys, tempfile
from pathlib import Path
import asyncio
import aiofiles
from tqdm.asyncio import tqdm

# --- Configuration and Utility Functions ---

META_FILENAME = "HASH_META.json"
SALT_BYTES = 16

def ensure_dir(p: Path):
    p.mkdir(parents=True, exist_ok=True)

def atomic_write(path: Path, data: bytes):
    dirpath = path.parent
    ensure_dir(dirpath)
    fd, tmp = tempfile.mkstemp(prefix=".tmp_hash_", dir=str(dirpath))
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data); f.flush(); os.fsync(f.fileno())
        os.replace(tmp, str(path))
    finally:
        if os.path.exists(tmp):
            try: os.remove(tmp)
            except: pass

def initial_hmac(data: bytes, salt: bytes):
    h = hmac.new(salt, digestmod="sha256")
    h.update(data)
    return h.digest()

def avalanche_mix(seed: bytes, salt: bytes, rounds: int):
    digest = seed
    for i in range(rounds):
        m = hashlib.sha3_512()
        m.update(digest)
        m.update(salt)
        m.update(i.to_bytes(2, "big"))
        digest = m.digest()
    return digest

def compute_digest(data: bytes, salt: bytes, avalanche: bool, rounds: int):
    seed = initial_hmac(data, salt)
    return avalanche_mix(seed, salt, rounds) if avalanche else seed

def relative_paths(root: Path):
    file_list = []
    for p in root.rglob("*"):
        if p.is_file() and p.name != META_FILENAME:
            file_list.append((p, p.relative_to(root)))
    return file_list

def write_meta(meta, root: Path):
    atomic_write(root / META_FILENAME, json.dumps(meta, indent=2).encode())

# --- Core Asynchronous Hashing Function ---

async def async_process_file(abs_path: Path, rel: Path, target_dir: Path, mode: str, av: bool, rounds: int):
    async with aiofiles.open(abs_path, "rb") as f:
        data = await f.read()

    salt = secrets.token_bytes(SALT_BYTES)
    digest = await asyncio.to_thread(compute_digest, data, salt, av, rounds)
    digest_hex = digest.hex()

    if mode == "1":
        async with aiofiles.open(abs_path, "wb") as f:
            await f.write(digest_hex.encode())
        action = "[OVERWROTE]"
    else:
        dest = target_dir / rel
        dest.parent.mkdir(parents=True, exist_ok=True) 
        async with aiofiles.open(dest, "wb") as f:
            await f.write(digest_hex.encode())
        action = "[COPIED→HASHED]"

    return str(rel), {"salt": salt.hex(), "digest": digest_hex, "avalanche": av, "rounds": rounds}, action

# --- Main Asynchronous Runner ---

async def process_single_directory(source_dir: Path, out_dir: Path, mode: str, av: bool, rounds: int):
    if not source_dir.exists() or not source_dir.is_dir():
        print(f"\n[SKIP] Source directory not found: {source_dir}")
        return
        
    print(f"\n--- Processing Directory: {source_dir} ---")

    files_to_process = relative_paths(source_dir)
    if not files_to_process:
        print(f"[INFO] No files found.")
        return

    tasks = [async_process_file(abs, rel, out_dir, mode, av, rounds) 
             for abs, rel in files_to_process]
    
    meta = {}
    results = await tqdm(asyncio.gather(*tasks, return_exceptions=True), 
                         total=len(tasks), desc=f"Hashing {source_dir.name}")

    for result in results:
        if isinstance(result, Exception):
            print(f"\n[ERROR] Exception: {result}")
            continue
            
        rel_str, file_meta, action = result
        meta[rel_str] = file_meta
    
    write_meta(meta, out_dir)

    print(f"\nCompleted: {source_dir}")
    print(f"Meta written to: {out_dir}")

async def main():
    print("\n=== CBI INDUSTRIES – AVALANCHE HASH SYSTEM ===\n")

    target_input = input("Directories (comma-separated): ").strip()
    source_dirs = [Path(t.strip()).expanduser().resolve() for t in target_input.split(',') if t.strip()]

    mode = input("\nMode:\n  1) Overwrite (destructive)\n  2) Copy hashed\nSelect 1 or 2: ").strip()

    av = input("\nAvalanche mode? (y/n): ").strip().lower() == "y"
    rounds = int(input("Rounds (3–10): ").strip()) if av else 0

    if mode == "1":
        confirm = input("Type YES to confirm destructive overwrite: ").strip()
        if confirm != "YES":
            print("Cancelled.")
            sys.exit(0)
        dir_targets = [(src, src) for src in source_dirs]
    else:
        out_target = Path(input("\nOutput directory: ").strip()).expanduser().resolve()
        ensure_dir(out_target)
        dir_targets = [(src, out_target) for src in source_dirs]
    
    for src_dir, out_dir in dir_targets:
        await process_single_directory(src_dir, out_dir, mode, av, rounds)

    print("\n=== PROCESS COMPLETE ===\n")

if __name__ == "__main__":
    asyncio.run(main())
