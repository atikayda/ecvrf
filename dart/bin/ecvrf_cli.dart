// CLI wrapper for cross-implementation validation.
//
// Usage:
//   ecvrf-cli prove <sk_hex> <alpha_hex|--alpha-file path>
//   ecvrf-cli verify <pk_hex> <pi_hex> <alpha_hex|--alpha-file path>
//
// Prints one JSON object: {"pi":..,"beta":..} for prove, or
// {"valid":..,"beta":..|null} for verify.
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:ecvrf/ecvrf.dart';

Never _fail(String message) {
  stderr.writeln(message);
  exit(1);
}

Uint8List _hexDecode(String hex, String what) {
  if (hex.length.isOdd || !RegExp(r'^[0-9a-fA-F]*$').hasMatch(hex)) {
    _fail('invalid $what hex');
  }
  final out = Uint8List(hex.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(hex.substring(2 * i, 2 * i + 2), radix: 16);
  }
  return out;
}

String _hexEncode(Uint8List bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

String _readAlpha(List<String> args, int idx) {
  if (args[idx] == '--alpha-file') {
    if (args.length <= idx + 1) _fail('--alpha-file needs a path');
    try {
      return File(args[idx + 1]).readAsStringSync().trim();
    } on FileSystemException catch (e) {
      _fail('reading alpha file: ${e.message}');
    }
  }
  return args[idx];
}

void main(List<String> args) {
  if (args.isEmpty) _fail('usage: ecvrf-cli prove|verify ...');

  switch (args[0]) {
    case 'prove':
      if (args.length < 3) {
        _fail('usage: ecvrf-cli prove <sk_hex> <alpha_hex|--alpha-file path>');
      }
      final sk = _hexDecode(args[1], 'sk');
      final alpha = _hexDecode(_readAlpha(args, 2), 'alpha');
      final Uint8List pi;
      final Uint8List beta;
      try {
        pi = prove(sk, alpha);
        beta = proofToHash(pi);
      } on ArgumentError catch (e) {
        _fail('prove failed: ${e.message}');
      }
      stdout.writeln(
        jsonEncode({'pi': _hexEncode(pi), 'beta': _hexEncode(beta)}),
      );

    case 'verify':
      if (args.length < 4) {
        _fail(
          'usage: ecvrf-cli verify <pk_hex> <pi_hex> '
          '<alpha_hex|--alpha-file path>',
        );
      }
      final pk = _hexDecode(args[1], 'pk');
      final pi = _hexDecode(args[2], 'pi');
      final alpha = _hexDecode(_readAlpha(args, 3), 'alpha');
      final result = verify(pk, pi, alpha);
      final beta = result.beta;
      stdout.writeln(
        jsonEncode({
          'valid': result.valid,
          'beta': beta == null ? null : _hexEncode(beta),
        }),
      );

    default:
      _fail('unknown command: ${args[0]}');
  }
}
