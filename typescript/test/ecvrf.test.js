import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { hexToBytes } from '@noble/curves/utils.js';
import {
  prove,
  verify,
  proofToHash,
  getPublicKey,
} from '../dist/ecvrf.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const vectorsPath = resolve(__dirname, '../../vectors/vectors.json');
const data = JSON.parse(readFileSync(vectorsPath, 'utf-8'));

function toHex(bytes) {
  return Buffer.from(bytes).toString('hex');
}

describe('ECVRF-SECP256K1-SHA256-TAI positive vectors', () => {
  for (const vec of data.vectors) {
    const label = vec.label || `sk=${vec.sk.slice(0, 8)}… alpha=${vec.alpha.slice(0, 16)}…`;

    it(`prove: ${label}`, () => {
      const sk = hexToBytes(vec.sk);
      const alpha = hexToBytes(vec.alpha);
      const pi = prove(sk, alpha);
      assert.equal(toHex(pi), vec.pi, 'pi must be byte-identical');
    });

    it(`proofToHash: ${label}`, () => {
      const pi = hexToBytes(vec.pi);
      const beta = proofToHash(pi);
      assert.equal(toHex(beta), vec.beta, 'beta must be byte-identical');
    });

    it(`verify: ${label}`, () => {
      const pk = hexToBytes(vec.pk);
      const pi = hexToBytes(vec.pi);
      const alpha = hexToBytes(vec.alpha);
      const result = verify(pk, pi, alpha);
      assert.equal(result.valid, true, 'proof must verify');
      assert.equal(toHex(result.beta), vec.beta, 'verify beta must match');
    });

    it(`getPublicKey: ${label}`, () => {
      const sk = hexToBytes(vec.sk);
      const pk = getPublicKey(sk);
      assert.equal(toHex(pk), vec.pk, 'derived pk must match');
    });

    it(`determinism: ${label}`, () => {
      const sk = hexToBytes(vec.sk);
      const alpha = hexToBytes(vec.alpha);
      const pi1 = prove(sk, alpha);
      const pi2 = prove(sk, alpha);
      assert.deepEqual(pi1, pi2, 'prove must be deterministic');
    });

    it(`round-trip: ${label}`, () => {
      const sk = hexToBytes(vec.sk);
      const alpha = hexToBytes(vec.alpha);
      const pi = prove(sk, alpha);
      const beta = proofToHash(pi);
      const pk = getPublicKey(sk);
      const result = verify(pk, pi, alpha);
      assert.equal(result.valid, true, 'own proof must verify');
      assert.equal(toHex(result.beta), toHex(beta), 'verify beta must equal proofToHash beta');
      assert.equal(toHex(result.beta), vec.beta, 'round-trip beta must match vector');
    });
  }
});

describe('ECVRF-SECP256K1-SHA256-TAI invalid SK rejection', () => {
  const GROUP_ORDER = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');

  function bigintToBytes(n, len) {
    const hex = n.toString(16).padStart(len * 2, '0');
    return hexToBytes(hex);
  }

  it('reject: zero secret key', () => {
    assert.throws(() => prove(new Uint8Array(32), new Uint8Array([0x74, 0x65, 0x73, 0x74])));
  });

  it('reject: sk = group order n', () => {
    assert.throws(() => prove(bigintToBytes(GROUP_ORDER, 32), new Uint8Array([0x74, 0x65, 0x73, 0x74])));
  });

  it('reject: sk = n + 1', () => {
    assert.throws(() => prove(bigintToBytes(GROUP_ORDER + 1n, 32), new Uint8Array([0x74, 0x65, 0x73, 0x74])));
  });
});

describe('ECVRF-SECP256K1-SHA256-TAI negative vectors', () => {
  for (const vec of data.negative_vectors) {
    it(`reject: ${vec.description}`, () => {
      const pk = hexToBytes(vec.pk);
      const pi = hexToBytes(vec.pi);
      const alpha = hexToBytes(vec.alpha);
      const result = verify(pk, pi, alpha);
      assert.equal(result.valid, false, `must reject: ${vec.description}`);
    });
  }
});
