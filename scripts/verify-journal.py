#!/usr/bin/env python3
"""Verifies a doorward decision journal without doorward.

Reads decision records as JSON lines (a file, or standard input) and checks
that each record's chain.hash is the SHA-256 of the record in RFC 8785
canonical JSON without chain.hash, and that each record follows the one
before it (seq + 1, prev equal to the previous hash).

This is a second, independent implementation of the chain: it shares no
code with doorward, so a journal it accepts can be trusted without
trusting the box. Python 3 standard library only.

usage: verify-journal.py [FILE]
exit status: 0 intact, 1 broken, 2 unreadable
"""

import base64
import hashlib
import json
import math
import sys


def canonical(v):
    """RFC 8785: JSON Canonicalization Scheme."""
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, str):
        return string(v)
    if isinstance(v, (int, float)):
        return number(v)
    if isinstance(v, list):
        return "[" + ",".join(canonical(x) for x in v) + "]"
    if isinstance(v, dict):
        keys = sorted(v, key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(string(k) + ":" + canonical(v[k]) for k in keys) + "}"
    raise TypeError(f"not a JSON value: {v!r}")


def string(s):
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif o < 0x20:
            out.append(f"\\u{o:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def number(x):
    """A number as ECMAScript's Number.prototype.toString writes it."""
    f = float(x)
    if math.isnan(f) or math.isinf(f):
        raise ValueError(f"{x} is not a JSON number")
    if f == 0:
        return "0"
    sign = "-" if f < 0 else ""
    r = repr(abs(f))  # the shortest digits that read back to the same double
    mantissa, _, exp = r.partition("e")
    whole, _, frac = mantissa.partition(".")
    s = whole + frac
    lead = len(s) - len(s.lstrip("0"))
    digits = s.strip("0")
    n = len(whole) + (int(exp) if exp else 0) - lead  # where the point falls
    k = len(digits)
    if k <= n <= 21:
        out = digits + "0" * (n - k)
    elif 0 < n <= 21:
        out = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        out = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        out = digits[0] + ("." + digits[1:] if k > 1 else "") + "e" + ("+" if e > 0 else "-") + str(abs(e))
    return sign + out


def digest(data):
    return "sha-256:" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


def main():
    try:
        src = open(sys.argv[1], encoding="utf-8") if len(sys.argv) > 1 else sys.stdin
        lines = [line for line in src.read().splitlines() if line.strip()]
    except OSError as e:
        print(f"verify-journal: {e}", file=sys.stderr)
        return 2
    records = []
    for i, line in enumerate(lines):
        try:
            record = json.loads(line)
            records.append((record["chain"]["seq"], record))
        except (ValueError, KeyError, TypeError) as e:
            print(f"line {i + 1}: unreadable: {e}", file=sys.stderr)
            return 2
    # Lines may arrive in any order (several files concatenated): the chain
    # is checked in sequence order.
    records.sort(key=lambda r: r[0])
    prev = None
    for i, (_, record) in enumerate(records):
        chain = record["chain"]
        claimed = chain.pop("hash")
        if prev is not None and chain.get("seq") == prev[0]:
            print(f"seq {chain.get('seq')} appears twice", file=sys.stderr)
            return 1
        if digest(canonical(record).encode("utf-8")) != claimed:
            print(f"record {i} (seq {chain.get('seq')}, {record.get('id')}): hash does not match its contents", file=sys.stderr)
            return 1
        if prev is not None and (chain.get("seq") != prev[0] + 1 or chain.get("prev") != prev[1]):
            print(f"record {i} (seq {chain.get('seq')}, {record.get('id')}): does not follow seq {prev[0]}", file=sys.stderr)
            return 1
        prev = (chain.get("seq"), claimed)
    if prev is None:
        print("no records")
        return 0
    print(f"{len(lines)} records, chain intact, head seq {prev[0]} hash {prev[1]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
