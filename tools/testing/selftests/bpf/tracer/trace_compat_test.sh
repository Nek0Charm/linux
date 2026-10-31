#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
set -euo pipefail
cd "$(dirname "$0")"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

${CC:-cc} ${CFLAGS:--O2 -Wall -Wextra -Werror} -I. \
	trace_consumer.c trace_compat_test.c -o "$work/compat"
env -u TRACE_FIXTURE_FILE "$work/compat" > "$work/compat.json"
python3 - "$work/compat.json" <<'PY'
import json
import sys

with open(sys.argv[1]) as source:
    runs = json.load(source)
assert len(runs) == 5

def number(value):
    return int(value, 0) if isinstance(value, str) else value

for run in runs:
    # Match every mandatory field read by validator/main.ml, including fields
    # that are only populated when a program performs a tail call.
    assert isinstance(run['prog_name'], str)
    assert isinstance(run['prog_insn'], list)
    assert isinstance(run['trace'], list)
    assert isinstance(run['sp_list'], list)
    assert isinstance(run['jmp_max_entries'], int)
    number(run['ctx_ptr'])
    number(run['jmp_map_ptr'])
    for block in run['mem_blocks']:
        number(block['base_addr'])
        assert isinstance(block['size'], int)
    for entry in run['jmp_table']:
        assert isinstance(entry['index'], int)
        number(entry['target'])
        assert entry['insns']
        list(map(number, entry['insns']))

assert runs[0]['capture_status'] == 'complete'
assert list(map(number, runs[0]['sp_list'])) == [0x8020]
assert list(map(number, runs[1]['sp_list'])) == [0x8020, 0x7040, 0x7040]
assert runs[1]['capture_status'] == 'complete'
for run in runs[:2]:
    assert number(run['jmp_map_ptr']) == 0
    assert run['jmp_max_entries'] == 0
    assert run['jmp_table'] == []

tail = runs[2]
assert tail['capture_status'] == 'complete'
assert list(map(number, tail['sp_list'])) == [0x8200]
assert number(tail['jmp_map_ptr']) == 0x4000
assert tail['jmp_max_entries'] == 8
assert [entry['index'] for entry in tail['jmp_table']] == [2, 5, 2]
for entry in tail['jmp_table']:
    code = tail['codes'][entry['code_id']]
    assert entry['target'] == code['target']
    assert entry['insns'] == code['insns']
assert tail['jmp_table'][0]['insns'] != tail['jmp_table'][1]['insns']
assert runs[3]['capture_status'] == 'incomplete'
assert 'invalid_reference' in runs[3]['capture_reasons']
assert runs[3]['jmp_table'] == []
assert runs[4]['capture_status'] == 'incomplete'
assert 'missing_end' in runs[4]['capture_reasons']
print('trace JSON compatibility tests passed')
PY
