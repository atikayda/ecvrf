#!/usr/bin/env bash
set -euo pipefail

# Cross-implementation validation for ECVRF-SECP256K1-SHA256-TAI
# Verifies all prove-capable implementations produce byte-identical output
# and can verify each other's proofs. Solana participates as verify-only.
#
# Set ECVRF_BIN_DIR to a directory containing pre-built CLI binaries to skip
# all build steps. Expected layout inside ECVRF_BIN_DIR:
#   go/ecvrf-go, rust/cli, c/ecvrf_cli, haskell/ecvrf-cli, zig/ecvrf-cli,
#   solana/cli, kotlin/ (installDist tree), csharp/ (dotnet publish output),
#   typescript/ (dist/ + node-cli.mjs), swift/ecvrf-cli (optional)
# Python and Solidity use scripts from the source tree (no pre-built binary).

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

if [ -n "${ECVRF_BIN_DIR:-}" ]; then
    bold "Using pre-built binaries from $ECVRF_BIN_DIR"

    GO_CLI="$ECVRF_BIN_DIR/go/ecvrf-go"
    RUST_CLI="$ECVRF_BIN_DIR/rust/cli"
    C_CLI="$ECVRF_BIN_DIR/c/ecvrf_cli"
    HASKELL_CLI="$ECVRF_BIN_DIR/haskell/ecvrf-cli"
    ZIG_CLI="$ECVRF_BIN_DIR/zig/ecvrf-cli"
    SOLANA_CLI="$ECVRF_BIN_DIR/solana/cli"
    KOTLIN_CLI="$ECVRF_BIN_DIR/kotlin/bin/ecvrf-kotlin"
    CSHARP_CLI_DIR="$ECVRF_BIN_DIR/csharp"
    NODE_CLI="$ECVRF_BIN_DIR/typescript/node-cli.mjs"

    # Python uses source-tree scripts (interpreted)
    PYTHON="python3"
    PY_CLI="$ROOT/scripts/python-cli.py"

    # Solidity (optional — needs forge runtime)
    SOLIDITY_AVAILABLE=false
    SOLIDITY_CLI=""
    if command -v forge &>/dev/null && [ -d "$ROOT/solidity/lib/forge-std" ]; then
        SOLIDITY_CLI="$ROOT/scripts/solidity-cli.sh"
        SOLIDITY_AVAILABLE=true
    else
        echo "  Solidity: forge or forge-std not available, skipping"
    fi

    # Swift (optional — pre-built binary may not exist)
    SWIFT_AVAILABLE=false
    SWIFT_CLI=""
    if [ -x "$ECVRF_BIN_DIR/swift/ecvrf-cli" ]; then
        SWIFT_CLI="$ECVRF_BIN_DIR/swift/ecvrf-cli"
        SWIFT_AVAILABLE=true
    fi

    # Make downloaded binaries executable
    for bin in "$GO_CLI" "$RUST_CLI" "$C_CLI" "$HASKELL_CLI" "$ZIG_CLI" "$SOLANA_CLI" "$KOTLIN_CLI"; do
        [ -f "$bin" ] && chmod +x "$bin"
    done
    # Make Kotlin wrapper scripts executable
    if [ -d "$ECVRF_BIN_DIR/kotlin/bin" ]; then
        chmod +x "$ECVRF_BIN_DIR/kotlin/bin/"* 2>/dev/null || true
    fi
    # Make source-tree scripts executable (git perms may not survive all CI environments)
    for script in "$SOLIDITY_CLI" "$PY_CLI"; do
        [ -f "$script" ] && chmod +x "$script"
    done

    CSHARP_PREBUILT=true
    bold "Pre-built binaries ready."
else
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

    # Solidity (optional — needs forge)
    SOLIDITY_AVAILABLE=false
    SOLIDITY_CLI=""
    if command -v forge &>/dev/null; then
        if (cd "$ROOT/solidity" && {
            [ -d lib/forge-std ] || {
                git init 2>/dev/null
                forge install foundry-rs/forge-std --no-git 2>/dev/null
            }
            forge build --quiet 2>/dev/null
        }); then
            SOLIDITY_CLI="$ROOT/scripts/solidity-cli.sh"
            SOLIDITY_AVAILABLE=true
        else
            echo "  Solidity build failed, skipping"
        fi
    else
        echo "  Forge toolchain not found, skipping Solidity"
    fi

    # Solana (verify-only CLI)
    (cd "$ROOT/solana" && cargo build --example cli --features no-entrypoint --release 2>/dev/null) || {
        red "Solana build failed"; exit 1
    }
    SOLANA_CLI="$ROOT/solana/target/release/examples/cli"

    GO_CLI="$ROOT/scripts/.bin/ecvrf-go"
    PY_CLI="$ROOT/scripts/python-cli.py"
    CSHARP_PREBUILT=false

    SKIPPED=""
    [ "$SWIFT_AVAILABLE" = "false" ] && SKIPPED="Swift"
    [ "$SOLIDITY_AVAILABLE" = "false" ] && SKIPPED="${SKIPPED:+$SKIPPED, }Solidity"
    if [ -z "$SKIPPED" ]; then
        bold "All builds succeeded."
    else
        bold "Builds succeeded ($SKIPPED skipped)."
    fi
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

# Determine prover/verifier counts dynamically
NUM_PROVERS=9
[ "$SOLIDITY_AVAILABLE" = "true" ] && NUM_PROVERS=$((NUM_PROVERS + 1))
[ "$SWIFT_AVAILABLE" = "true" ] && NUM_PROVERS=$((NUM_PROVERS + 1))
NUM_VERIFIERS=$((NUM_PROVERS + 1))

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
csharp_prebuilt = '$CSHARP_PREBUILT' == 'true'
kotlin_cli = '$KOTLIN_CLI'
haskell_cli = '$HASKELL_CLI'
zig_cli = '$ZIG_CLI'
swift_cli = '$SWIFT_CLI'
swift_available = '$SWIFT_AVAILABLE' == 'true'
solidity_cli = '$SOLIDITY_CLI'
solidity_available = '$SOLIDITY_AVAILABLE' == 'true'

pass_count = 0
fail_count = 0

def csharp_cmd(*args):
    if csharp_prebuilt:
        return ['dotnet', 'exec', csharp_dir + '/Ecvrf.Cli.dll'] + list(args)
    return ['dotnet', 'run', '--project', csharp_dir, '-c', 'Release', '--no-build', '--'] + list(args)

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
        'csharp':     csharp_cmd('prove', sk) + aa,
        'kotlin':     [kotlin_cli, 'prove', sk] + aa,
        'haskell':    [haskell_cli, 'prove', sk] + aa,
        'zig':        [zig_cli, 'prove', sk] + aa,
    }
    if solidity_available:
        cmds['solidity'] = ['bash', solidity_cli, 'prove', sk] + aa
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
csharp_prebuilt = '$CSHARP_PREBUILT' == 'true'
kotlin_cli = '$KOTLIN_CLI'
haskell_cli = '$HASKELL_CLI'
zig_cli = '$ZIG_CLI'
swift_cli = '$SWIFT_CLI'
swift_available = '$SWIFT_AVAILABLE' == 'true'
solidity_cli = '$SOLIDITY_CLI'
solidity_available = '$SOLIDITY_AVAILABLE' == 'true'
solana_cli = '$SOLANA_CLI'

def csharp_cmd(*args):
    if csharp_prebuilt:
        return ['dotnet', 'exec', csharp_dir + '/Ecvrf.Cli.dll'] + list(args)
    return ['dotnet', 'run', '--project', csharp_dir, '-c', 'Release', '--no-build', '--'] + list(args)

prover_impls = ['go', 'python', 'rust', 'typescript', 'c', 'csharp', 'kotlin', 'haskell', 'zig']
if solidity_available:
    prover_impls.append('solidity')
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
        'csharp':     csharp_cmd('prove', sk) + aa,
        'kotlin':     [kotlin_cli, 'prove', sk] + aa,
        'haskell':    [haskell_cli, 'prove', sk] + aa,
        'zig':        [zig_cli, 'prove', sk] + aa,
    }
    if solidity_available:
        cmds['solidity'] = ['bash', solidity_cli, 'prove', sk] + aa
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
        'csharp':     csharp_cmd('verify', pk, pi) + aa,
        'kotlin':     [kotlin_cli, 'verify', pk, pi] + aa,
        'haskell':    [haskell_cli, 'verify', pk, pi] + aa,
        'zig':        [zig_cli, 'verify', pk, pi] + aa,
        'solana':     [solana_cli, 'verify', pk, pi] + aa,
    }
    if solidity_available:
        cmds['solidity'] = ['bash', solidity_cli, 'verify', pk, pi] + aa
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
csharp_prebuilt = '$CSHARP_PREBUILT' == 'true'
kotlin_cli = '$KOTLIN_CLI'
haskell_cli = '$HASKELL_CLI'
zig_cli = '$ZIG_CLI'
swift_cli = '$SWIFT_CLI'
swift_available = '$SWIFT_AVAILABLE' == 'true'
solidity_cli = '$SOLIDITY_CLI'
solidity_available = '$SOLIDITY_AVAILABLE' == 'true'
solana_cli = '$SOLANA_CLI'

def csharp_cmd(*args):
    if csharp_prebuilt:
        return ['dotnet', 'exec', csharp_dir + '/Ecvrf.Cli.dll'] + list(args)
    return ['dotnet', 'run', '--project', csharp_dir, '-c', 'Release', '--no-build', '--'] + list(args)

verifier_names = ['go', 'python', 'rust', 'typescript', 'c', 'csharp', 'kotlin', 'haskell', 'zig']
if solidity_available:
    verifier_names.append('solidity')
if swift_available:
    verifier_names.append('swift')
verifier_names.append('solana')

def verify_cmd(impl, pk, pi, aa):
    cmds = {
        'go':         [go_cli, 'verify', pk, pi] + aa,
        'python':     [python, py_cli, 'verify', pk, pi] + aa,
        'rust':       [rust_cli, 'verify', pk, pi] + aa,
        'typescript': ['node', node_cli, 'verify', pk, pi] + aa,
        'c':          [c_cli, 'verify', pk, pi] + aa,
        'csharp':     csharp_cmd('verify', pk, pi) + aa,
        'kotlin':     [kotlin_cli, 'verify', pk, pi] + aa,
        'haskell':    [haskell_cli, 'verify', pk, pi] + aa,
        'zig':        [zig_cli, 'verify', pk, pi] + aa,
        'solana':     [solana_cli, 'verify', pk, pi] + aa,
    }
    if solidity_available:
        cmds['solidity'] = ['bash', solidity_cli, 'verify', pk, pi] + aa
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
echo "  - Prove identity: all ${NUM_PROVERS} implementations produce byte-identical pi and beta"
echo "  - Cross-verification: ${NUM_PROVERS}x${NUM_VERIFIERS} matrix of prove/verify combinations all succeed"
echo "  - Negative rejection: all ${NUM_VERIFIERS} implementations reject all invalid proofs"
[ "$SOLIDITY_AVAILABLE" = "false" ] && echo "  - Solidity: skipped (forge not available in this environment)"
[ "$SWIFT_AVAILABLE" = "false" ] && echo "  - Swift: skipped (toolchain not available on this platform)"
echo "  - Solana: participates as verify-only (no prove capability)"
echo ""
