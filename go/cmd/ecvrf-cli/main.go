// CLI wrapper for cross-implementation validation.
// Usage:
//
//	ecvrf-cli prove <sk_hex> <alpha_hex>
//	ecvrf-cli verify <pk_hex> <pi_hex> <alpha_hex>
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/atikayda/ecvrf"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: ecvrf-cli prove|verify ...")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "prove":
		if len(os.Args) != 4 {
			fmt.Fprintln(os.Stderr, "usage: ecvrf-cli prove <sk_hex> <alpha_hex>")
			os.Exit(1)
		}
		sk, err := hex.DecodeString(os.Args[2])
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid sk hex: %v\n", err)
			os.Exit(1)
		}
		alpha, err := hex.DecodeString(os.Args[3])
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid alpha hex: %v\n", err)
			os.Exit(1)
		}
		pi, err := ecvrf.Prove(sk, alpha)
		if err != nil {
			fmt.Fprintf(os.Stderr, "prove failed: %v\n", err)
			os.Exit(1)
		}
		beta, err := ecvrf.ProofToHash(pi)
		if err != nil {
			fmt.Fprintf(os.Stderr, "proof_to_hash failed: %v\n", err)
			os.Exit(1)
		}
		out, _ := json.Marshal(map[string]string{
			"pi":   hex.EncodeToString(pi),
			"beta": hex.EncodeToString(beta),
		})
		fmt.Println(string(out))

	case "verify":
		if len(os.Args) != 5 {
			fmt.Fprintln(os.Stderr, "usage: ecvrf-cli verify <pk_hex> <pi_hex> <alpha_hex>")
			os.Exit(1)
		}
		pk, err := hex.DecodeString(os.Args[2])
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid pk hex: %v\n", err)
			os.Exit(1)
		}
		pi, err := hex.DecodeString(os.Args[3])
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid pi hex: %v\n", err)
			os.Exit(1)
		}
		alpha, err := hex.DecodeString(os.Args[4])
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid alpha hex: %v\n", err)
			os.Exit(1)
		}
		valid, beta := ecvrf.Verify(pk, pi, alpha)
		result := map[string]interface{}{"valid": valid, "beta": nil}
		if beta != nil {
			result["beta"] = hex.EncodeToString(beta)
		}
		out, _ := json.Marshal(result)
		fmt.Println(string(out))

	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}
