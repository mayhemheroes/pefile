#!/usr/bin/env bash
#
# pefile/mayhem/test.sh — behavioral oracle for erocarrera/pefile.
#
# It RUNS the real parser (via the /mayhem/run-cli launcher built by mayhem/build.sh) over the
# bundled appendtofile.exe PE fixture and ASSERTS the decoded header/section values (known-answer
# test): DOS magic, NT signature, machine, optional-header magic, entrypoint, image base, and the
# section table. This exercises the SAME pipeline the fuzzer drives — file read -> pefile.PE parse
# -> header/section decode — so a no-op/neutered program (no output, or wrong output) FAILS here.
# It never builds; it only runs the pre-built launcher.
#
# Anti-reward-hack note: run-cli lives at /mayhem (a NON-system path), so the verify-repo sabotage
# neuter (_exit(0) on non-system exes) trips it -> empty output -> assertions fail -> detected.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=/mayhem}"
cd "$SRC"

CLI="$SRC/run-cli"
EXE="$SRC/mayhem/fuzz-exe/testsuite/appendtofile.exe"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

PASS=0; FAIL=0
check() { # check <name> <condition-rc>
  if [ "$2" -eq 0 ]; then echo "PASS: $1"; PASS=$((PASS+1)); else echo "FAIL: $1"; FAIL=$((FAIL+1)); fi
}

if [ ! -x "$CLI" ]; then
  echo "missing $CLI — run mayhem/build.sh first" >&2
  emit_ctrf "pefile-knownanswer" 0 1 0; exit 2
fi
if [ ! -f "$EXE" ]; then
  echo "missing $EXE" >&2
  emit_ctrf "pefile-knownanswer" 0 1 0; exit 2
fi

echo "=== parsing appendtofile.exe (header/section dump to stdout) ==="
OUT="$("$CLI" "$EXE" 2>/dev/null)"
echo "$OUT"

# Known answers for the bundled appendtofile.exe fixture (PE32+ x86-64 console, 11 sections).
grep -q '^e_magic=0x5a4d$'                <<<"$OUT"; check "DOS e_magic (MZ)" $?
grep -q '^Signature=0x00004550$'          <<<"$OUT"; check "NT signature (PE\0\0)" $?
grep -q '^Machine=0x8664$'                <<<"$OUT"; check "Machine (x86-64)" $?
grep -q '^NumberOfSections=11$'           <<<"$OUT"; check "NumberOfSections" $?
grep -q '^Magic=0x020b$'                  <<<"$OUT"; check "Optional header Magic (PE32+)" $?
grep -q '^AddressOfEntryPoint=0x1125$'    <<<"$OUT"; check "AddressOfEntryPoint" $?
grep -q '^ImageBase=0x140000000$'         <<<"$OUT"; check "ImageBase" $?
grep -q '^Subsystem=3$'                   <<<"$OUT"; check "Subsystem (console)" $?
grep -q '^is_exe=True$'                   <<<"$OUT"; check "is_exe" $?
grep -q '^is_dll=False$'                  <<<"$OUT"; check "is_dll" $?
grep -q '^Section=.text,VA=0x1000,Raw=0x2000$'  <<<"$OUT"; check ".text section entry" $?
grep -q '^Section=.rdata,VA=0x4000,Raw=0x600$'  <<<"$OUT"; check ".rdata section entry" $?
grep -q '^Section=.reloc,VA=0xc000,Raw=0x200$'  <<<"$OUT"; check ".reloc section entry" $?

emit_ctrf "pefile-knownanswer" "$PASS" "$FAIL" 0
