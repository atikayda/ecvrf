#!/usr/bin/env bash
set -euo pipefail

# Cross-implementation validation for ECVRF-SECP256K1-SHA256-TAI
# Verifies all prove-capable implementations produce byte-identical output
# and can verify each other's proofs. Solana participates as verify-only.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VECTORS="$ROOT/vectors/vectors.json"
PASS=0
FAIL=0
TOTAL=0

red()   { printf '\033[0;31m%s\033[0m\n' "$*"; }
green() { printf '\033[0;32m%s\033[0m\n' "$*"; }
bold()  { printf '\033[1m%s\033[0m\n' "$*"; }

check() {
    TOTAL=$((TOTAL + 1))
    if [ "$1" = "$2" ]; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        red "  FAIL: $3"
        red "    expected: $1"
        red "    got:      $2"
    fi
}

# Ensure ghcup binaries (cabal, ghc) are on PATH
export PATH="$HOME/.ghcup/bin:$PATH"

# ── Prerequisites ──────────────────────────────────────────────────────

bold "Building implementations..."

# Go
(cd "$ROOT/go" && go build -o "$ROOT/scripts/.bin/ecvrf-go" ./cmd/ecvrf-cli) || {
    red "Go build failed"; exit 1
}

# Rust
(cd "$ROOT/rust" && cargo build --example cli --release 2>/dev/null) || {
    red "Rust build failed"; exit 1
}
RUST_CLI="$ROOT/rust/target/release/examples/cli"

# Python venv
PYTHON="$ROOT/python/.venv/bin/python3"
if [ ! -x "$PYTHON" ]; then
    PYTHON="python3"
fi

# Node
NODE_CLI="$ROOT/scripts/node-cli.mjs"

# C
(cd "$ROOT/c" && make ecvrf_cli 2>/dev/null) || {
    red "C build failed"; exit 1
}
C_CLI="$ROOT/c/ecvrf_cli"

# C#
(cd "$ROOT/csharp/Ecvrf.Cli" && dotnet build -c Release --nologo -v q 2>/dev/null) || {
    red "C# build failed"; exit 1
}
CSHARP_CLI_DIR="$ROOT/csharp/Ecvrf.Cli"

# Kotlin
(cd "$ROOT/kotlin" && ./gradlew installDist --quiet 2>/dev/null) || {
    red "Kotlin build failed"; exit 1
}
KOTLIN_CLI="$ROOT/kotlin/build/install/ecvrf-kotlin/bin/ecvrf-kotlin"

# Haskell
(cd "$ROOT/haskell" && cabal build ecvrf-cli 2>/dev/null) || {
    red "Haskell build failed"; exit 1
}
HASKELL_CLI="$(cd "$ROOT/haskell" && cabal list-bin ecvrf-cli 2>/dev/null)"

# Zig
(cd "$ROOT/zig" && zig build -Doptimize=ReleaseFast 2>/dev/null) || {
    red "Zig build failed"; exit 1
}
ZIG_CLI="$ROOT/zig/zig-out/bin/ecvrf-cli"

# Swift (optional — not available on all platforms, e.g. Ubuntu CI)
SWIFT_AVAILABLE=false
SWIFT_CLI=""
if command -v swift &>/dev/null; then
    if (cd "$ROOT/swift" && swift build -c release --quiet 2>/dev/null); then
        SWIFT_CLI="$(cd "$ROOT/swift" && swift build -c release --show-bin-path 2>/dev/null)/ecvrf-cli"
        SWIFT_AVAILABLE=true
    else
        echo "  Swift build failed, skipping"
    fi
else
    echo "  Swift toolchain not found, skipping"
fi

# Solidity (needs forge; install forge-std if missing)
(cd "$ROOT/solidity" && {
    [ -d lib/forge-std ] || {
        git init 2>/dev/null
        forge install foundry-rs/forge-std --no-git 2>/dev/null
    }
    forge build --quiet 2>/dev/null
}) || {
    red "Solidity build failed"; exit 1
}
SOLIDITY_CLI="$ROOT/scripts/solidity-cli.sh"

# Solana (verify-only CLI)
(cd "$ROOT/solana" && cargo build --example cli --features no-entrypoint --release 2>/dev/null) || {
    red "Solana build failed"; exit 1
}
SOLANA_CLI="$ROOT/solana/target/release/examples/cli"

GO_CLI="$ROOT/scripts/.bin/ecvrf-go"
PY_CLI="$ROOT/scripts/python-cli.py"

if [ "$SWIFT_AVAILABLE" = "true" ]; then
    bold "All builds succeeded."
else
    bold "Builds succeeded (Swift skipped — toolchain not available)."
fi
echo ""

# ── Extract test vectors ───────────────────────────────────────────────

VECTOR_INDICES="0 1 2 7 22 30 39 50"
SUBSET_FILE="$(mktemp)"
trap 'rm -f "$SUBSET_FILE"' EXIT

"$PYTHON" -c "
import json, sys
with open('$VECTORS') as f:
    data = json.load(f)
vecs = data['vectors']
indices = [int(i) for i in '$VECTOR_INDICES'.split() if int(i) < len(vecs)]
subset = [vecs[i] for i in indices]
with open('$SUBSET_FILE', 'w') as out:
    json.dump(subset, out)
"

NUM_VECTORS=$("$PYTHON" -c "import json; print(len(json.load(open('$SUBSET_FILE'))))")

# Determine prover/verifier counts
if [ "$SWIFT_AVAILABLE" = "true" ]; then
    NUM_PROVERS=11
    NUM_VERIFIERS=12
else
    NUM_PROVERS=10
    NUM_VERIFIERS=11
fi

bold "=== Phase 1: Prove Identity (${NUM_VECTORS} vectors, ${NUM_PROVERS} implementations) ==="
echo "All prove-capable implementations must produce the same pi and beta for identical inputs."
echo ""

# ── Phase 1: Prove Identity ───────────────────────────────────────────

"$PYTHON" -c "
import json, subprocess, sys, os, tempfile, atexit

_alpha_fd, _alpha_path = tempfile.mkstemp(prefix='ecvrf-alpha-')
os.close(_alpha_fd)
atexit.register(lambda: os.path.exists(_alpha_path) and os.unlink(_alpha_path))

def alpha_args(alpha_hex):
    with open(_alpha_path, 'w') as f:
        f.write(alpha_hex)
    return ['--alpha-file', _alpha_path]

with open('$SUBSET_FILE') as f:
    vectors = json.load(f)

go_cli = '$GO_CLI'
rust_cli = '$RUST_CLI'
py_cli = '$PY_CLI'
node_cli = '$NODE_CLI'
python = '$PYTHON'
c_cli = '$C_CLI'
csharp_dir = '$CSHARP_CLI_DIR'
kotlin_cli = '$KOTLIN_CLI'
haskell_cli = '$HASKELL_CLI'
zig_cli = '$ZIG_CLI'
swift_cli = '$SWIFT_CLI'
swift_available = '$SWIFT_AVAILABLE' == 'true'
solidity_cli = '$SOLIDITY_CLI'

pass_count = 0
fail_count = 0

def run_cmd(cmd, cwd=None):
    out = subprocess.check_output(cmd, timeout=120, stderr=subprocess.DEVNULL, cwd=cwd)
    return json.loads(out)

for i, vec in enumerate(vectors):
    sk = vec['sk']
    alpha = vec['alpha']
    label = vec['label']
    expected_pi = vec['pi']
    expected_beta = vec['beta']

    print(f'  Vector {i}: {label}')

    results = {}
    aa = alpha_args(alpha)

    cmds = {
        'go':         [go_cli, 'prove', sk] + aa,
        'python':     [python, py_cli, 'prove', sk] + aa,
        'rust':       [rust_cli, 'prove', sk] + aa,
        'typescript': ['node', node_cli, 'prove', sk] + aa,
        'c':          [c_cli, 'prove', sk] + aa,
        'csharp':     ['dotnet', 'run', '--project', csharp_dir, '-c', 'Release', '--no-build', '--', 'prove', sk] + aa,
        'kotlin':     [kotlin_cli, 'prove', sk] + aa,
        'haskell':    [haskell_cli, 'prove', sk] + aa,
        'zig':        [zig_cli, 'prove', sk] + aa,
        'solidity':   ['bash', solidity_cli, 'prove', sk] + aa,
    }
    if swift_available:
        cmds['swift'] = [swift_cli, 'prove', sk] + aa

    NUM_PROVERS = len(cmds)

    for lang, cmd in cmds.items():
        try:
            results[lang] = run_cmd(cmd)
        except Exception as e:
            results[lang] = {'error': str(e)}

    all_match = True
    for lang, res in results.items():
        if 'error' in res:
            print(f'    \033[0;31mFAIL {lang}: {res[\"error\"]}\033[0m')
            all_match = False
            continue
        if res['pi'] != expected_pi:
            print(f'    \033[0;31mFAIL {lang} pi mismatch\033[0m')
            print(f'      expected: {expected_pi}')
            print(f'      got:      {res[\"pi\"]}')
            all_match = False
        if res['beta'] != expected_beta:
            print(f'    \033[0;31mFAIL {lang} beta mismatch\033[0m')
            all_match = False

    if all_match:
        print(f'    \033[0;32mPASS — all {NUM_PROVERS} implementations match\033[0m')
        pass_count += 1
    else:
        fail_count += 1

print()
print(f'  Phase 1 results: {pass_count} passed, {fail_count} failed')
if fail_count > 0:
    sys.exit(1)
"

echo ""
bold "=== Phase 2: Cross-Verification Matrix ==="
echo "Proof from implementation A verified by implementation B (including Solana verify-only)."
echo ""

# ── Phase 2: Cross-Verification ───────────────────────────────────────

"$PYTHON" -c "
import json, subprocess, sys, os, tempfile, atexit

_alpha_fd, _alpha_path = tempfile.mkstemp(prefix='ecvrf-alpha-')
os.close(_alpha_fd)
atexit.register(lambda: os.path.exists(_alpha_path) and os.unlink(_alpha_path))

def alpha_args(alpha_hex):
    with open(_alpha_path, 'w') as f:
        f.write(alpha_hex)
    return ['--alpha-file', _alpha_path]

with open('$SUBSET_FILE') as f:
    vectors = json.load(f)

go_cli = '$GO_CLI'
rust_cli = '$RUST_CLI'
py_cli = '$PY_CLI'
node_cli = '$NODE_CLI'
python = '$PYTHON'
c_cli = '$C_CLI'
csharp_dir = '$CSHARP_CLI_DIR'
kotlin_cli = '$KOTLIN_CLI'
haskell_cli = '$HASKELL_CLI'
zig_cli = '$ZIG_CLI'
swift_cli = '$SWIFT_CLI'
swift_available = '$SWIFT_AVAILABLE' == 'true'
solidity_cli = '$SOLIDITY_CLI'
solana_cli = '$SOLANA_CLI'

prover_impls = ['go', 'python', 'rust', 'typescript', 'c', 'csharp', 'kotlin', 'haskell', 'zig', 'solidity']
if swift_available:
    prover_impls.append('swift')
verifier_impls = prover_impls + ['solana']

def prove_cmd(impl, sk, aa):
    cmds = {
        'go':         [go_cli, 'prove', sk] + aa,
        'python':     [python, py_cli, 'prove', sk] + aa,
        'rust':       [rust_cli, 'prove', sk] + aa,
        'typescript': ['node', node_cli, 'prove', sk] + aa,
        'c':          [c_cli, 'prove', sk] + aa,
        'csharp':     ['dotnet', 'run', '--project', csharp_dir, '-c', 'Release', '--no-build', '--', 'prove', sk] + aa,
        'kotlin':     [kotlin_cli, 'prove', sk] + aa,
        'haskell':    [haskell_cli, 'prove', sk] + aa,
        'zig':        [zig_cli, 'prove', sk] + aa,
        'solidity':   ['bash', solidity_cli, 'prove', sk] + aa,
    }
    if swift_available:
        cmds['swift'] = [swift_cli, 'prove', sk] + aa
    return cmds[impl]

def verify_cmd(impl, pk, pi, aa):
    cmds = {
        'go':         [go_cli, 'verify', pk, pi] + aa,
        'python':     [python, py_cli, 'verify', pk, pi] + aa,
        'rust':       [rust_cli, 'verify', pk, pi] + aa,
        'typescript': ['node', node_cli, 'verify', pk, pi] + aa,
        'c':          [c_cli, 'verify', pk, pi] + aa,
        'csharp':     ['dotnet', 'run', '--project', csharp_dir, '-c', 'Release', '--no-build', '--', 'verify', pk, pi] + aa,
        'kotlin':     [kotlin_cli, 'verify', pk, pi] + aa,
        'haskell':    [haskell_cli, 'verify', pk, pi] + aa,
        'zig':        [zig_cli, 'verify', pk, pi] + aa,
        'solidity':   ['bash', solidity_cli, 'verify', pk, pi] + aa,
        'solana':     [solana_cli, 'verify', pk, pi] + aa,
    }
    if swift_available:
        cmds['swift'] = [swift_cli, 'verify', pk, pi] + aa
    return cmds[impl]

def run_cmd(cmd):
    out = subprocess.check_output(cmd, timeout=120, stderr=subprocess.DEVNULL)
    return json.loads(out)

pass_count = 0
fail_count = 0

for vec in vectors[:3]:
    sk = vec['sk']
    pk = vec['pk']
    alpha = vec['alpha']
    label = vec['label']
    expected_beta = vec['beta']

    print(f'  Vector: {label}')

    vec_failed = False
    for prover in prover_impls:
        aa = alpha_args(alpha)
        proof = run_cmd(prove_cmd(prover, sk, aa))
        pi = proof['pi']

        for verifier in verifier_impls:
            aa = alpha_args(alpha)
            result = run_cmd(verify_cmd(verifier, pk, pi, aa))
            ok = result['valid'] and result.get('beta') == expected_beta

            tag = f'{prover} -> {verifier}'
            if ok:
                pass_count += 1
            else:
                fail_count += 1
                vec_failed = True
                print(f'    \033[0;31mFAIL {tag}: valid={result[\"valid\"]}, beta={result.get(\"beta\")}\033[0m')

    if not vec_failed:
        print(f'    \033[0;32mPASS — all {len(prover_impls)}x{len(verifier_impls)} cross-verifications passed\033[0m')

print()
print(f'  Phase 2 results: {pass_count} passed, {fail_count} failed')
if fail_count > 0:
    sys.exit(1)
"

echo ""
bold "=== Phase 3: Negative Vector Rejection ==="
echo "All implementations (including Solana) must reject every negative vector."
echo ""

# ── Phase 3: Negative Vector Rejection ────────────────────────────────

"$PYTHON" -c "
import json, subprocess, sys, os, tempfile, atexit

_alpha_fd, _alpha_path = tempfile.mkstemp(prefix='ecvrf-alpha-')
os.close(_alpha_fd)
atexit.register(lambda: os.path.exists(_alpha_path) and os.unlink(_alpha_path))

def alpha_args(alpha_hex):
    with open(_alpha_path, 'w') as f:
        f.write(alpha_hex)
    return ['--alpha-file', _alpha_path]

with open('$VECTORS') as f:
    data = json.load(f)

neg_vectors = data['negative_vectors']

go_cli = '$GO_CLI'
rust_cli = '$RUST_CLI'
py_cli = '$PY_CLI'
node_cli = '$NODE_CLI'
python = '$PYTHON'
c_cli = '$C_CLI'
csharp_dir = '$CSHARP_CLI_DIR'
kotlin_cli = '$KOTLIN_CLI'
haskell_cli = '$HASKELL_CLI'
zig_cli = '$ZIG_CLI'
swift_cli = '$SWIFT_CLI'
swift_available = '$SWIFT_AVAILABLE' == 'true'
solidity_cli = '$SOLIDITY_CLI'
solana_cli = '$SOLANA_CLI'

verifier_names = ['go', 'python', 'rust', 'typescript', 'c', 'csharp', 'kotlin', 'haskell', 'zig', 'solidity', 'solana']
if swift_available:
    verifier_names.insert(-1, 'swift')  # before solana

def verify_cmd(impl, pk, pi, aa):
    cmds = {
        'go':         [go_cli, 'verify', pk, pi] + aa,
        'python':     [python, py_cli, 'verify', pk, pi] + aa,
        'rust':       [rust_cli, 'verify', pk, pi] + aa,
        'typescript': ['node', node_cli, 'verify', pk, pi] + aa,
        'c':          [c_cli, 'verify', pk, pi] + aa,
        'csharp':     ['dotnet', 'run', '--project', csharp_dir, '-c', 'Release', '--no-build', '--', 'verify', pk, pi] + aa,
        'kotlin':     [kotlin_cli, 'verify', pk, pi] + aa,
        'haskell':    [haskell_cli, 'verify', pk, pi] + aa,
        'zig':        [zig_cli, 'verify', pk, pi] + aa,
        'solidity':   ['bash', solidity_cli, 'verify', pk, pi] + aa,
        'solana':     [solana_cli, 'verify', pk, pi] + aa,
    }
    if swift_available:
        cmds['swift'] = [swift_cli, 'verify', pk, pi] + aa
    return cmds[impl]

pass_count = 0
fail_count = 0

for vec in neg_vectors:
    pk = vec['pk']
    alpha = vec['alpha']
    pi = vec['pi']
    desc = vec['description']

    results = {}
    aa = alpha_args(alpha)

    for name in verifier_names:
        try:
            out = subprocess.check_output(verify_cmd(name, pk, pi, aa), timeout=120, stderr=subprocess.DEVNULL)
            results[name] = json.loads(out)
        except subprocess.CalledProcessError:
            results[name] = {'valid': False, 'beta': None}
        except Exception as e:
            results[name] = {'valid': True, 'error': str(e)}

    all_rejected = all(not r.get('valid', True) for r in results.values())

    if all_rejected:
        pass_count += 1
    else:
        fail_count += 1
        accepted_by = [n for n, r in results.items() if r.get('valid', False)]
        print(f'  \033[0;31mFAIL \"{desc}\" accepted by: {accepted_by}\033[0m')

print(f'  {pass_count}/{len(neg_vectors)} negative vectors correctly rejected by all implementations')
if fail_count > 0:
    sys.exit(1)
else:
    print(f'  \033[0;32mPASS\033[0m')
"

echo ""
bold "=== Summary ==="
green "All cross-implementation validation checks passed."
if [ "$SWIFT_AVAILABLE" = "true" ]; then
    echo "  - Prove identity: all 11 implementations produce byte-identical pi and beta"
    echo "  - Cross-verification: 11x12 matrix of prove/verify combinations all succeed"
    echo "  - Negative rejection: all 12 implementations reject all invalid proofs"
else
    echo "  - Prove identity: all 10 implementations produce byte-identical pi and beta"
    echo "  - Cross-verification: 10x11 matrix of prove/verify combinations all succeed"
    echo "  - Negative rejection: all 11 implementations reject all invalid proofs"
    echo "  - Swift: skipped (toolchain not available on this platform)"
fi
echo "  - Solana: participates as verify-only (no prove capability)"
echo ""
