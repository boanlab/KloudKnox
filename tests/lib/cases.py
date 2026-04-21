#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Minimal parser for cases/test-cases.yaml — avoids the PyYAML dependency.
#
# Strict schema (2-space indent throughout):
#
#   - id: <str>
#     name: <str>
#     policy: <path relative to tests>
#     steps:
#       - pod: <label>
#         exec: <command-line>
#         expect: allowed | blocked | audited
#         timeout: <seconds>         # optional, default 15
#
# Comments (`#`) and blank lines are ignored. Values may be single- or
# double-quoted; unquoted values are taken verbatim (after trim).

import json
import re
import sys
from pathlib import Path


def _strip_comment(s: str) -> str:
    in_s = in_d = False
    for i, ch in enumerate(s):
        if ch == "'" and not in_d:
            in_s = not in_s
        elif ch == '"' and not in_s:
            in_d = not in_d
        elif ch == '#' and not in_s and not in_d:
            return s[:i].rstrip()
    return s.rstrip()


def _unquote(s: str):
    s = s.strip()
    if len(s) >= 2 and s[0] == '[' and s[-1] == ']':
        items = [item.strip().strip("'\"") for item in s[1:-1].split(',')]
        return [item for item in items if item]
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"'):
        return s[1:-1]
    if re.fullmatch(r"-?\d+", s):
        return int(s)
    if re.fullmatch(r"-?\d+\.\d+", s):
        return float(s)
    return s


def _split_kv(line: str):
    key, _, val = line.partition(':')
    return key.strip(), val.strip()


def _tokenize(path: Path):
    out = []
    for raw in path.read_text().splitlines():
        stripped = _strip_comment(raw)
        if not stripped.strip():
            continue
        indent = len(raw) - len(raw.lstrip(' '))
        out.append((indent, stripped.strip()))
    return out


def parse(path: Path):
    toks = _tokenize(path)
    cases = []
    i = 0
    while i < len(toks):
        indent, text = toks[i]
        if indent != 0 or not text.startswith('- '):
            raise SyntaxError(f"line {i+1}: expected top-level '- id: ...': {text!r}")
        case = {}
        k, v = _split_kv(text[2:])
        case[k] = _unquote(v)
        i += 1
        while i < len(toks):
            ci, ct = toks[i]
            if ci == 0:
                break
            if ci != 2:
                raise SyntaxError(f"line {i+1}: case body must be indent=2: {ct!r}")
            k, v = _split_kv(ct)
            if v == '':
                if k != 'steps':
                    raise SyntaxError(f"line {i+1}: only 'steps' may introduce a block: {ct!r}")
                i += 1
                case['steps'] = []
                while i < len(toks):
                    si, st = toks[i]
                    if si <= 2:
                        break
                    if si != 4 or not st.startswith('- '):
                        raise SyntaxError(f"line {i+1}: step must start with '- pod:' at indent 4: {st!r}")
                    step = {}
                    kk, vv = _split_kv(st[2:])
                    step[kk] = _unquote(vv)
                    i += 1
                    while i < len(toks):
                        ti, tt = toks[i]
                        if ti <= 4:
                            break
                        if ti != 6:
                            raise SyntaxError(f"line {i+1}: step body must be indent=6: {tt!r}")
                        kk, vv = _split_kv(tt)
                        step[kk] = _unquote(vv)
                        i += 1
                    case['steps'].append(step)
                continue
            case[k] = _unquote(v)
            i += 1
        cases.append(case)
    return cases


def _synonyms(case):
    ids = set()
    if 'id' in case:
        ids.add(str(case['id']))
    if 'policy' in case:
        ids.add(Path(case['policy']).stem)
    return ids


def cmd_ids(path):
    for c in parse(path):
        print(c.get('id') or Path(c.get('policy', '')).stem)


def cmd_ids_excluding(path, tag):
    for c in parse(path):
        tags = c.get('tags', [])
        if isinstance(tags, list) and tag in tags:
            continue
        print(c.get('id') or Path(c.get('policy', '')).stem)


def cmd_list(path):
    for c in parse(path):
        cid = c.get('id', '?')
        name = c.get('name', '')
        print(f"{cid:<10}  {name}")


def cmd_get(path, needle):
    for c in parse(path):
        if needle in _synonyms(c):
            print(json.dumps(c))
            return 0
    print(f"case not found: {needle}", file=sys.stderr)
    return 1


def main(argv):
    if len(argv) < 3:
        print("usage: cases.py <ids|list|get> <file> [id]", file=sys.stderr)
        return 2
    sub, file_arg = argv[1], argv[2]
    path = Path(file_arg)
    if not path.exists():
        print(f"missing: {path}", file=sys.stderr)
        return 2
    if sub == 'ids':
        cmd_ids(path); return 0
    if sub == 'ids-excluding':
        if len(argv) < 4:
            print("usage: cases.py ids-excluding <file> <tag>", file=sys.stderr)
            return 2
        cmd_ids_excluding(path, argv[3]); return 0
    if sub == 'list':
        cmd_list(path); return 0
    if sub == 'get':
        if len(argv) < 4:
            print("usage: cases.py get <file> <id>", file=sys.stderr)
            return 2
        return cmd_get(path, argv[3])
    print(f"unknown subcommand: {sub}", file=sys.stderr)
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv))
