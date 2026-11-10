/// Pure-Dart elliptic curve cryptography on Curve256189.
///
/// Provides X256189 ECDH, Ed256189 and XEdDSA signatures, Elligator 2,
/// HKDF, and AES-256-GCM. See the package README for usage and the `doc/`
/// directory for the specifications.
library curve256189;

// Export all source files
export 'src/aesgcm.dart';
export 'src/batch_verify.dart';
export 'src/edwards.dart';
export 'src/eddsa256189.dart';
export 'src/eddsa256189_batch.dart';
export 'src/elligator.dart';
export 'src/field.dart';
export 'src/hkdf.dart';
export 'src/montgomery.dart';
export 'src/params.dart';
export 'src/x256189.dart';
export 'src/xeddsa.dart';
