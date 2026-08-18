#!/usr/bin/env python3
"""Fail if any source file contains raw control bytes.

Control characters inside a regex character class do work, but they make the
source unreviewable, and a NUL byte in a committed file breaks a range of
tooling. Escape sequences (\\u0000) are the reviewable form. Run this in CI.
"""
import pathlib
import sys

SKIP = {".git", "node_modules", ".next", ".sst", ".open-next", "coverage"}
ALLOWED = {0x09, 0x0A, 0x0D}  # tab, LF, CR
EXTS = {".ts", ".tsx", ".js", ".mjs", ".json", ".md", ".css", ".py", ".yml", ".yaml"}

bad = []
for f in pathlib.Path(".").rglob("*"):
    if not f.is_file() or SKIP & set(f.parts) or f.suffix not in EXTS:
        continue
    for i, c in enumerate(f.read_bytes()):
        if (c < 0x20 and c not in ALLOWED) or c == 0x7F:
            bad.append(f"{f}: byte {hex(c)} at offset {i}")
            break

if bad:
    print("Raw control bytes found (use \\uXXXX escapes instead):")
    for b in bad:
        print(f"  {b}")
    sys.exit(1)
print(f"No raw control bytes in source.")
