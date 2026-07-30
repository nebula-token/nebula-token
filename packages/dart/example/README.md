# nebula_token example

The runnable template in this directory is
[`sql_store_example.dart`](sql_store_example.dart): a production-style,
driver-agnostic `RefreshTokenStore` written against a two-method `SqlExecutor`
abstraction, so it compiles with no database driver present and drops onto
`package:postgres`, `mysql_client` or `sqlite3` unchanged.

The store adapter is the part every adopter writes themselves, and the two
mutating methods are compare-and-sets — the status predicate belongs in the
`WHERE` clause and the affected-row count is the return value. That is what
makes reuse detection work under concurrency; `UPDATE … WHERE selector = ?`
alone silently forks the token family.

Minimal usage, with the in-memory store:

```dart
import 'dart:io';

import 'package:nebula_token/nebula_token.dart';

Future<void> main() async {
  final engine = NebulaEngine(
    peppers: {'k1': Platform.environment['NEBULA_PEPPER_K1']!}, // >= 32 bytes
    activeKid: 'k1',
    store: MemoryRefreshTokenStore(), // swap for SqlRefreshTokenStore
    reuseGraceSeconds: 0,          // strict; see [N-30] before raising this
  );

  final issued = await engine.issue('usr_1'); // deviceId is optional

  final result = await engine.refresh(issued.token);
  switch (result) {
    case RefreshSuccess(:final token):
      stdout.writeln('rotated: $token');
    case RefreshFailure(:final error):
      stdout.writeln('refused: ${error.code}');
  }
}
```
