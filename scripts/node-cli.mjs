#!/usr/bin/env node
/**
 * CLI wrapper for ECVRF TypeScript implementation — cross-validation use only.
 */
import { prove, verify, proofToHash, getPublicKey } from '../typescript/dist/ecvrf.js';

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

const [,, cmd, ...args] = process.argv;

if (cmd === 'prove') {
  const [skHex, alphaHex] = args;
  const sk = hexToBytes(skHex);
  const alpha = hexToBytes(alphaHex);
  const pi = prove(sk, alpha);
  const beta = proofToHash(pi);
  console.log(JSON.stringify({ pi: bytesToHex(pi), beta: bytesToHex(beta) }));
} else if (cmd === 'verify') {
  const [pkHex, piHex, alphaHex] = args;
  const pk = hexToBytes(pkHex);
  const pi = hexToBytes(piHex);
  const alpha = hexToBytes(alphaHex);
  const result = verify(pk, pi, alpha);
  console.log(JSON.stringify({
    valid: result.valid,
    beta: result.beta ? bytesToHex(result.beta) : null,
  }));
} else {
  console.error(`unknown command: ${cmd}`);
  process.exit(1);
}
