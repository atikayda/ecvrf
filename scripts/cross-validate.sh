#!/usr/bin/env bash
set -euo pipefail

# Cross-implementation validation for ECVRF-SECP256K1-SHA256-TAI
# Verifies all 4 implementations produce byte-identical output and can
# verify each other's proofs.

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

GO_CLI="$ROOT/scripts/.bin/ecvrf-go"
PY_CLI="$ROOT/scripts/python-cli.py"

bold "All builds succeeded."
echo ""

# ── Extract test vectors ───────────────────────────────────────────────

# Use Python to extract a diverse subset of vectors into a temp file
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

bold "=== Phase 1: Prove Identity (${NUM_VECTORS} vectors) ==="
echo "All implementations must produce the same pi and beta for identical inputs."
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

pass_count = 0
fail_count = 0

for i, vec in enumerate(vectors):
    sk = vec['sk']
    alpha = vec['alpha']
    label = vec['label']
    expected_pi = vec['pi']
    expected_beta = vec['beta']

    print(f'  Vector {i}: {label}')

    results = {}
    aa = alpha_args(alpha)

    # Go
    try:
        out = subprocess.check_output([go_cli, 'prove', sk] + aa, timeout=30)
        results['go'] = json.loads(out)
    except Exception as e:
        results['go'] = {'error': str(e)}

    # Python
    try:
        out = subprocess.check_output([python, py_cli, 'prove', sk] + aa, timeout=30)
        results['python'] = json.loads(out)
    except Exception as e:
        results['python'] = {'error': str(e)}

    # Rust
    try:
        out = subprocess.check_output([rust_cli, 'prove', sk] + aa, timeout=30)
        results['rust'] = json.loads(out)
    except Exception as e:
        results['rust'] = {'error': str(e)}

    # TypeScript
    try:
        out = subprocess.check_output(['node', node_cli, 'prove', sk] + aa, timeout=30)
        results['typescript'] = json.loads(out)
    except Exception as e:
        results['typescript'] = {'error': str(e)}

    # Check all match expected
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
        print(f'    \033[0;32mPASS — all 4 implementations match\033[0m')
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
echo "Proof from implementation A verified by implementation B."
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

impls = ['go', 'python', 'rust', 'typescript']

def do_prove(impl_name, sk, alpha):
    aa = alpha_args(alpha)
    if impl_name == 'go':
        out = subprocess.check_output([go_cli, 'prove', sk] + aa, timeout=30)
    elif impl_name == 'python':
        out = subprocess.check_output([python, py_cli, 'prove', sk] + aa, timeout=30)
    elif impl_name == 'rust':
        out = subprocess.check_output([rust_cli, 'prove', sk] + aa, timeout=30)
    elif impl_name == 'typescript':
        out = subprocess.check_output(['node', node_cli, 'prove', sk] + aa, timeout=30)
    return json.loads(out)

def do_verify(impl_name, pk, pi, alpha):
    aa = alpha_args(alpha)
    if impl_name == 'go':
        out = subprocess.check_output([go_cli, 'verify', pk, pi] + aa, timeout=30)
    elif impl_name == 'python':
        out = subprocess.check_output([python, py_cli, 'verify', pk, pi] + aa, timeout=30)
    elif impl_name == 'rust':
        out = subprocess.check_output([rust_cli, 'verify', pk, pi] + aa, timeout=30)
    elif impl_name == 'typescript':
        out = subprocess.check_output(['node', node_cli, 'verify', pk, pi] + aa, timeout=30)
    return json.loads(out)

pass_count = 0
fail_count = 0

# Use first 3 vectors for cross-verification (NxN is 4x4x3 = 48 verification calls)
for vec in vectors[:3]:
    sk = vec['sk']
    pk = vec['pk']
    alpha = vec['alpha']
    label = vec['label']
    expected_beta = vec['beta']

    print(f'  Vector: {label}')

    vec_failed = False
    for prover in impls:
        proof = do_prove(prover, sk, alpha)
        pi = proof['pi']

        for verifier in impls:
            result = do_verify(verifier, pk, pi, alpha)
            ok = result['valid'] and result.get('beta') == expected_beta

            tag = f'{prover} -> {verifier}'
            if ok:
                pass_count += 1
            else:
                fail_count += 1
                vec_failed = True
                print(f'    \033[0;31mFAIL {tag}: valid={result[\"valid\"]}, beta={result.get(\"beta\")}\033[0m')

    if not vec_failed:
        print(f'    \033[0;32mPASS — all {len(impls)}x{len(impls)} cross-verifications passed\033[0m')

print()
print(f'  Phase 2 results: {pass_count} passed, {fail_count} failed')
if fail_count > 0:
    sys.exit(1)
"

echo ""
bold "=== Phase 3: Negative Vector Rejection ==="
echo "All implementations must reject every negative vector."
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

pass_count = 0
fail_count = 0

for vec in neg_vectors:
    pk = vec['pk']
    alpha = vec['alpha']
    pi = vec['pi']
    desc = vec['description']

    results = {}
    aa = alpha_args(alpha)

    for name, cmd in [
        ('go', [go_cli, 'verify', pk, pi] + aa),
        ('python', [python, py_cli, 'verify', pk, pi] + aa),
        ('rust', [rust_cli, 'verify', pk, pi] + aa),
        ('typescript', ['node', node_cli, 'verify', pk, pi] + aa),
    ]:
        try:
            out = subprocess.check_output(cmd, timeout=30, stderr=subprocess.DEVNULL)
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
echo "  - Prove identity: all 4 implementations produce byte-identical pi and beta"
echo "  - Cross-verification: NxN matrix of prove/verify combinations all succeed"
echo "  - Negative rejection: all implementations reject all invalid proofs"
