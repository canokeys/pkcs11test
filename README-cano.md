# CanoKey Windows/PIV Test Profile

This profile extends the archived PKCS#11 v2.2 test suite for CanoKey's
PIV-oriented PKCS#11 module. The generic suite remains available for other
tokens; CanoKey-specific tests use PIV object IDs, policies, and binary
management-key authentication.

## Build

Run from this checkout in a VS 2022 developer prompt with ClangCL and Ninja.
`<canokey-pkcs11-source>` is the local CanoKey PKCS#11 source checkout.

```powershell
cmake -S <canokey-pkcs11-source> -B canokey-pkcs11-build -G Ninja `
  -DCMAKE_C_COMPILER=clang-cl -DCMAKE_CXX_COMPILER=clang-cl `
  -DCMAKE_BUILD_TYPE=Debug -DBUILD_SHARED_LIBS=ON `
  -DBUILD_TESTING=OFF -DBUILD_UNIT_TESTING=OFF -DBUILD_REAL_TESTING=OFF
cmake --build canokey-pkcs11-build
cmake -S . -B test-build -G Ninja -DSTRICT_P11=ON
cmake --build test-build
```

The Windows port uses `LoadLibraryA`/`GetProcAddress`, accepts Windows path
separators, refreshes PC/SC slot IDs after reinitialization, and enables
`STRICT_P11` by default. The `-o-hex` option passes a binary SO credential with
an explicit length instead of treating it as a C string.

## Current Card

The development token currently reports slot `0`, serial `0`, and PIV ID 06 /
slot 83 contains an RSA-4096 key. Its independent ID 06 certificate object may
not match this generated key, so this slot is not suitable for Windows
certificate-propagation validation until a matching certificate is written.

## Destructive Tests

All CanoKey writes require `-D` and an expected serial via `-E`. The test source
fixes the target to ID 06 / PIV 83; callers cannot select another PIV slot.
Supply the binary management key with `-o-hex` and the USER PIN with `-u`.

EC P-256 generation:

```powershell
./test-build/pkcs11test.exe `
  -m canokey-pkcs11.dll -l ./canokey-pkcs11-build -S 0 `
  -u <user-pin> -o-hex <24-byte-management-key-in-hex> `
  -D -E 0 --gtest_filter=ReadWriteSessionTest.CanokeyDestructive*
```

RSA generation and use:

```powershell
./test-build/pkcs11test.exe `
  -m canokey-pkcs11.dll -l ./canokey-pkcs11-build -S 0 `
  -u <user-pin> -o-hex <24-byte-management-key-in-hex> `
  -D -E 0 --gtest_filter='RsaSizes/CanokeyDestructiveRsaTest.*'
```

The RSA profile covers 2048, 3072, and 4096 bits and verifies public
encryption, USER-authenticated private decryption, signing, and modulus-size
readback. Each parameter overwrites ID 06. Do not combine these tests with
`-I`; CanoKey intentionally does not implement generic `C_InitToken`.

## Current Results

The full no-SO profile runs 329 tests: 151 pass and 178 fail. The remaining
failures are expected for a PIV-only module and are not 178 independent bugs.

| Tests | Count | Why they fail |
| --- | ---: | --- |
| `Ciphers/SecretKeyTest` | 106 | Fixed DES/3DES/AES cipher fixtures require generic symmetric mechanisms that CanoKey does not expose. |
| `Signatures/SignTest` | 18 | Fixtures generate 1024-bit RSA keys in a read-only session without a PIV `CKA_ID`; PIV generation requires RW + SO + an explicit ID. |
| `ReadWriteSessionTest` | 12 | Generic DES/RSA/Tookan/session-object setup is outside the PIV object model and fails before a card call. |
| `HMACs/HmacTest` | 10 | Generic HMAC secret-key creation and HMAC mechanisms are not supported. |
| `ReadOnlySessionTest` | 6 | Five tests depend on generic temporary RSA/secret/HMAC objects; the wrong-PIN test uses a 12-byte PIN and gets `CKR_PIN_LEN_RANGE`. |
| `Digests/DigestTest` | 8 | `DigestKey` and `DigestKeyInvalid` first generate a DES key; ordinary SHA digest tests pass. |
| `DataObjectTest` | 7 | The suite creates public session `CKO_DATA`; CanoKey exposes PIV data objects as token-backed management objects. |
| `Duals/DualSecretKeyTest` | 4 | DES/3DES digest+encrypt combinations are unavailable. |
| `ROUserSessionTest` | 3 | Wrap/unwrap is unsupported and the fixture's DES3 setup fails. |
| `RWSOSessionTest` | 2 | The no-SO profile has no valid binary management-key login, so the SO fixture cannot enter its intended state. |
| `KeyPairTest` | 1 | Generic 1024-bit RSA temporary key generation is not a CanoKey PIV operation. |
| `RWEitherSessionTest` | 1 | Tookan setup requires generic DES/RSA temporary keys. |

The focused contract profile passes slot validation, fixed-field padding,
private-object visibility, digest operation state, invalid-session precedence,
and malformed `C_CreateObject` checks.
