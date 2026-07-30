#!/usr/bin/env python3
"""Zero-out leftover source path / source-snippet C-strings in a BPF object.

Keeps ELF structure intact: only overwrites matching bytes in-place with NULs.
.BTF / .BTF.ext offset tables stay valid (func_info still loads).
"""
from pathlib import Path
import re
import sys

# exact fragments
EXACT = (
    b"./mckill.bpf.c",
    b"mckill.bpf.c",
    b"/tmp/mckill/mckill.bpf.c",
    b"mckill.c",
    b"JAVA_NAME_LEN",
    b"JAVA_SCAN_LIMIT",
    b"JAVA_PATH_LEN",
    b"BUF_SIZE",
    b"MAX_MARKER_LEN",
    b"has_marker",
    b"select_marker",
    b"marker_len",
    b"mc_marker",
    b"search_ctx",
    b"static long jcb",
    b"static long mcb",
)

# regex for residual C snippets that still leak structure
# only match long-enough printable runs that look like our source
REGEXES = (
    re.compile(rb"__u32 jn = len >=[^\x00]*"),
    re.compile(rb"if \(jn > [^\x00]*"),
    re.compile(rb"if \(i > [^\x00]*"),
    re.compile(rb"if \(len < [^\x00]*"),
    re.compile(rb"s->marker = [^\x00]*"),
    re.compile(rb"bpf_loop\([^\x00]*"),
    re.compile(rb"has_marker\([^\x00]*"),
    re.compile(rb"static long jcb\([^\x00]*"),
    re.compile(rb"static long mcb\([^\x00]*"),
    re.compile(rb"switch \(s->marker\)[^\x00]*"),
)


def wipe(d: bytearray, start: int, n: int) -> None:
    d[start : start + n] = b"\0" * n


def main(path: str) -> None:
    p = Path(path)
    d = bytearray(p.read_bytes())

    for pat in EXACT:
        i = 0
        while True:
            j = d.find(pat, i)
            if j < 0:
                break
            wipe(d, j, len(pat))
            i = j + len(pat)

    for rx in REGEXES:
        for m in rx.finditer(bytes(d)):
            wipe(d, m.start(), m.end() - m.start())

    p.write_bytes(d)


if __name__ == "__main__":
    main(sys.argv[1])
