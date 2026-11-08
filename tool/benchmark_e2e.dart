// tool/benchmark_e2e.dart

// Curve256189 end-to-end performance benchmark.
//
// Measures the public Ed256189 and XEdDSA APIs, and compares Ed256189 batch
// verification with individual verification on the same signature sets.
//
// Each measurement uses a warm-up phase and several samples. The reported
// figure is the median per-operation time. Fixture setup is excluded from the
// timed sections.
//
// Run with:
//   dart run tool/benchmark_e2e.dart

import 'dart:io' show Platform;
import 'dart:typed_data';

import 'package:curve256189/curve256189.dart';

const int _fixtureCount = 32;
const int _samples = 21;
const List<int> _batchSizes = [1, 2, 4, 8, 16];

class _Result {
  final String name;
  final List<double> samplesUs;

  _Result(this.name, this.samplesUs);

  double get medianUs {
    final sorted = [...samplesUs]..sort();
    final middle = sorted.length ~/ 2;
    if (sorted.length.isOdd) {
      return sorted[middle];
    }
    return (sorted[middle - 1] + sorted[middle]) / 2;
  }

  double get meanUs =>
      samplesUs.reduce((left, right) => left + right) / samplesUs.length;

  double get minUs =>
      samplesUs.reduce((left, right) => left < right ? left : right);

  double get maxUs =>
      samplesUs.reduce((left, right) => left > right ? left : right);

  double get opsPerSecond => 1000000 / medianUs;
}

_Result _measure({
  required String name,
  required int warmup,
  required void Function(int index) operation,
  int samples = _samples,
}) {
  for (var i = 0; i < warmup; i++) {
    operation(i);
  }

  final sampleTimes = <double>[];
  for (var sample = 0; sample < samples; sample++) {
    final stopwatch = Stopwatch()..start();
    operation(sample);
    stopwatch.stop();
    sampleTimes.add(stopwatch.elapsedMicroseconds.toDouble());
  }

  return _Result(name, sampleTimes);
}

double _timeBatchOnce(List<Ed256189SignatureBundle> subset) {
  final stopwatch = Stopwatch()..start();
  Ed256189BatchVerify.verify(subset);
  stopwatch.stop();
  return stopwatch.elapsedMicroseconds.toDouble();
}

double _timeIndividualOnce(List<Ed256189SignatureBundle> subset) {
  final stopwatch = Stopwatch()..start();
  for (final bundle in subset) {
    Ed256189.verify(
      bundle.message,
      bundle.signature,
      bundle.publicKey,
    );
  }
  stopwatch.stop();
  return stopwatch.elapsedMicroseconds.toDouble();
}

({_Result batch, _Result individual}) _measureBatchPair({
  required int size,
  required List<Ed256189SignatureBundle> subset,
  required int samples,
}) {
  for (var i = 0; i < 2; i++) {
    Ed256189BatchVerify.verify(subset);
    for (final bundle in subset) {
      Ed256189.verify(
        bundle.message,
        bundle.signature,
        bundle.publicKey,
      );
    }
  }

  final batchTimes = <double>[];
  final individualTimes = <double>[];
  for (var sample = 0; sample < samples; sample++) {
    // Alternate the order to balance any drift in CPU frequency or JIT state.
    if (sample.isEven) {
      batchTimes.add(_timeBatchOnce(subset));
      individualTimes.add(_timeIndividualOnce(subset));
    } else {
      individualTimes.add(_timeIndividualOnce(subset));
      batchTimes.add(_timeBatchOnce(subset));
    }
  }

  return (
    batch: _Result(
      'Ed256189BatchVerify.verify($size)',
      batchTimes,
    ),
    individual: _Result(
      'Ed256189.verify x$size',
      individualTimes,
    ),
  );
}

String _duration(double micros) {
  if (micros >= 1000) {
    return '${(micros / 1000).toStringAsFixed(2)} ms';
  }
  return '${micros.toStringAsFixed(2)} us';
}

String _rate(double opsPerSecond) {
  if (opsPerSecond >= 1000) {
    return '${(opsPerSecond / 1000).toStringAsFixed(2)}k';
  }
  return opsPerSecond.toStringAsFixed(1);
}

void _printTable(String title, List<_Result> results) {
  print(title);
  print('-' * 96);
  print(
    '${'Operation'.padRight(34)}'
    '${'Median'.padLeft(12)}'
    '${'Mean'.padLeft(12)}'
    '${'Min'.padLeft(12)}'
    '${'Max'.padLeft(12)}'
    '${'Ops/sec'.padLeft(12)}',
  );
  for (final result in results) {
    print(
      '${result.name.padRight(34)}'
      '${_duration(result.medianUs).padLeft(12)}'
      '${_duration(result.meanUs).padLeft(12)}'
      '${_duration(result.minUs).padLeft(12)}'
      '${_duration(result.maxUs).padLeft(12)}'
      '${_rate(result.opsPerSecond).padLeft(12)}',
    );
  }
  print('');
}

Uint8List _seed(int index) {
  return Uint8List.fromList(
    List<int>.generate(32, (i) => (index * 37 + i * 11 + 0x5a) & 0xff),
  );
}

Uint8List _message(int index) {
  return Uint8List.fromList(
    List<int>.generate(48, (i) => (index * 53 + i * 7 + 0xa5) & 0xff),
  );
}

void main() {
  print('Curve256189 End-to-End Benchmark');
  print(
      'Dart ${Platform.version.split(' ').first} on ${Platform.operatingSystem}');
  print('Fixtures: $_fixtureCount, samples per measurement: $_samples');
  print('');

  final seeds = List<Uint8List>.generate(_fixtureCount, _seed);
  final messages = List<Uint8List>.generate(_fixtureCount, _message);

  final edKeyPairs = <Map<String, Uint8List>>[];
  final edSignatures = <Uint8List>[];
  for (var i = 0; i < _fixtureCount; i++) {
    final keyPair = Ed256189.generateKeyPair(seeds[i]);
    edKeyPairs.add(keyPair);
    edSignatures.add(Ed256189.sign(messages[i], keyPair['privateKey']!));
  }

  final xKeyPairs = <Map<String, Uint8List>>[];
  final xSignatures = <Uint8List>[];
  for (var i = 0; i < _fixtureCount; i++) {
    final keyPair = XEdDSA.generateKeyPair(seeds[i]);
    xKeyPairs.add(keyPair);
    xSignatures.add(XEdDSA.sign(messages[i], keyPair['privateKey']!));
  }

  for (var i = 0; i < _fixtureCount; i++) {
    if (!Ed256189.verify(
      messages[i],
      edSignatures[i],
      edKeyPairs[i]['publicKey']!,
    )) {
      throw StateError('Ed256189 fixture $i failed verification');
    }
    if (!XEdDSA.verify(
      messages[i],
      xSignatures[i],
      xKeyPairs[i]['publicKey']!,
    )) {
      throw StateError('XEdDSA fixture $i failed verification');
    }
  }

  final bundles = List<Ed256189SignatureBundle>.generate(
    _fixtureCount,
    (i) => Ed256189SignatureBundle(
      message: messages[i],
      signature: edSignatures[i],
      publicKey: edKeyPairs[i]['publicKey']!,
    ),
  );

  if (!Ed256189BatchVerify.verify(bundles)) {
    throw StateError('batch fixture failed verification');
  }

  final edResults = [
    _measure(
      name: 'Ed256189.generateKeyPair',
      warmup: 3,
      operation: (i) => Ed256189.generateKeyPair(seeds[i % _fixtureCount]),
    ),
    _measure(
      name: 'Ed256189.sign',
      warmup: 3,
      operation: (i) => Ed256189.sign(
        messages[i % _fixtureCount],
        edKeyPairs[i % _fixtureCount]['privateKey']!,
      ),
    ),
    _measure(
      name: 'Ed256189.verify',
      warmup: 3,
      operation: (i) => Ed256189.verify(
        messages[i % _fixtureCount],
        edSignatures[i % _fixtureCount],
        edKeyPairs[i % _fixtureCount]['publicKey']!,
      ),
    ),
  ];
  _printTable('Ed256189 operations (RFC 8032-shaped)', edResults);

  final xResults = [
    _measure(
      name: 'XEdDSA.generateKeyPair',
      warmup: 5,
      operation: (i) => XEdDSA.generateKeyPair(seeds[i % _fixtureCount]),
    ),
    _measure(
      name: 'XEdDSA.sign',
      warmup: 3,
      operation: (i) => XEdDSA.sign(
        messages[i % _fixtureCount],
        xKeyPairs[i % _fixtureCount]['privateKey']!,
      ),
    ),
    _measure(
      name: 'XEdDSA.verify',
      warmup: 3,
      operation: (i) => XEdDSA.verify(
        messages[i % _fixtureCount],
        xSignatures[i % _fixtureCount],
        xKeyPairs[i % _fixtureCount]['publicKey']!,
      ),
    ),
  ];
  _printTable(
    'XEdDSA operations (superseded; kept for compatibility)',
    xResults,
  );

  final batchResults = <int, _Result>{};
  final individualResults = <int, _Result>{};
  for (final size in _batchSizes) {
    final subset = bundles.sublist(0, size);
    final pair = _measureBatchPair(
      size: size,
      subset: subset,
      samples: _samples,
    );
    batchResults[size] = pair.batch;
    individualResults[size] = pair.individual;
  }

  print('Batch verification versus individual verification');
  print('');
  print(
    '${'Size'.padRight(8)}'
    '${'Batch median'.padLeft(16)}'
    '${'Individual median'.padLeft(20)}'
    '${'Speedup'.padLeft(12)}',
  );
  print('-' * 56);
  for (final size in _batchSizes) {
    final batch = batchResults[size]!;
    final individual = individualResults[size]!;
    final speedup = individual.medianUs / batch.medianUs;
    print(
      '${size.toString().padRight(8)}'
      '${_duration(batch.medianUs).padLeft(16)}'
      '${_duration(individual.medianUs).padLeft(20)}'
      '${'${speedup.toStringAsFixed(2)}x'.padLeft(12)}',
    );
  }
  print('');

  print('Notes');
  print('- Median of $_samples operations per measurement.');
  print('- Batch size 1 delegates to individual verification.');
  print('- Batch verification includes its internal random scalar generation.');
  print('- Speedup above 1.00x means batch verification is faster.');
  print('- Differences of a few percent are within measurement noise.');
  print('- Results are machine-specific; compare runs on the same host.');
}
