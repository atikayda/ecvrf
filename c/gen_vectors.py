#!/usr/bin/env python3
"""Generate C test vector data from vectors.json."""

import json
import sys


def c_string(s: str) -> str:
    """Emit a C string literal, splitting very long strings."""
    if len(s) <= 4000:
        return f'"{s}"'
    chunks = [s[i : i + 4000] for i in range(0, len(s), 4000)]
    return "\n    ".join(f'"{c}"' for c in chunks)


def main() -> None:
    path = sys.argv[1] if len(sys.argv) > 1 else "../vectors/vectors.json"
    with open(path) as f:
        data = json.load(f)

    print("/* Auto-generated from vectors.json — do not edit. */")
    print("#ifndef VECTORS_DATA_H")
    print("#define VECTORS_DATA_H")
    print()
    print("#include <stddef.h>")
    print()
    print("typedef struct {")
    print("    const char *label;")
    print("    const char *sk;")
    print("    const char *pk;")
    print("    const char *alpha;")
    print("    const char *pi;")
    print("    const char *beta;")
    print("} test_vector_t;")
    print()
    print("typedef struct {")
    print("    const char *description;")
    print("    const char *pk;")
    print("    const char *alpha;")
    print("    const char *pi;")
    print("    int expected_verify;")
    print("} neg_vector_t;")
    print()

    vecs = data["vectors"]
    print("static const test_vector_t TEST_VECTORS[] = {")
    for v in vecs:
        label = v["label"].replace("\\", "\\\\").replace('"', '\\"')
        print(
            f"    {{{c_string(label)}, {c_string(v['sk'])}, "
            f"{c_string(v['pk'])}, {c_string(v['alpha'])}, "
            f"{c_string(v['pi'])}, {c_string(v['beta'])}}},"
        )
    print("};")
    print(f"static const size_t NUM_TEST_VECTORS = {len(vecs)};")
    print()

    negs = data["negative_vectors"]
    print("static const neg_vector_t NEG_VECTORS[] = {")
    for v in negs:
        desc = v["description"].replace("\\", "\\\\").replace('"', '\\"')
        ev = 1 if v["expected_verify"] else 0
        print(
            f"    {{{c_string(desc)}, {c_string(v['pk'])}, "
            f"{c_string(v['alpha'])}, {c_string(v['pi'])}, {ev}}},"
        )
    print("};")
    print(f"static const size_t NUM_NEG_VECTORS = {len(negs)};")
    print()
    print("#endif")


if __name__ == "__main__":
    main()
