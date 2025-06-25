# Crypto Suite Kit

[![NPM Version](https://badge.fury.io/gh/colossusdigital%2FcryptoSuiteKit.svg)](https://www.npmjs.com/package/@colossusdigital/cryptosuitekit)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**A modern, type-safe, and extensible TypeScript library for handling common cryptographic operations across different curves and schemes like ECDSA, Schnorr, and EdDSA.**

This library provides a clean, unified API to validate, normalize, sign, and verify using various cryptographic systems, powered by the highly-audited [@noble/curves](https://github.com/paulmillr/noble-curves).

## Key Features

-   **Multi-Curve & Multi-Scheme:** Out-of-the-box support for `secp256k1` (with `ECDSA` & `Schnorr`) and `ed25519` (with `EdDSA`).
-   **Unified API:** A single entry point, `getCryptoSuite`, provides a complete set of tools tailored to your needs.
-   **Type-Safe:** Built entirely in TypeScript to prevent common errors and provide excellent autocompletion.
-   **Extensible by Design:** The architecture makes it simple to add new curves or schemes in the future.
-   **Zero Dependencies:** Relies only on `@noble/curves` and `@noble/hashes`, which have no further dependencies.

## Installation

```bash
npm install YOUR_PACKAGE_NAME
```
You will also need to have `@noble/curves` and `@noble/hashes` in your project.
```bash
npm install @noble/curves @noble/hashes
```

## Quick Start

Here is a complete example of validating a key, signing a message hash, and verifying the signature using `ECDSA` on the `secp256k1` curve.

```typescript
import { getCryptoSuite, KeyValidationError } from 'YOUR_PACKAGE_NAME';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/curves/abstract/utils';

// You would typically generate/store private keys securely
const privateKeyHex = 'a1b2c3d4...'; 
const uncompressedPublicKeyHex = '04...'; // The public key to validate

// 1. Get the cryptographic suite for your desired system
const ecdsaSuite = getCryptoSuite({
  curve: 'secp256k1',
  scheme: 'ECDSA',
});

try {
  // 2. Validate the public key and choose an output format
  const { publicKey: compressedPubKey } = ecdsaSuite.validateAndNormalizePublicKey(
    uncompressedPublicKeyHex,
    { outputFormat: 'compressed' }
  );
  console.log('Key is valid and compressed:', compressedPubKey);

  // 3. Prepare a message hash to sign
  const messageHash = bytesToHex(sha256('my important message'));

  // 4. Sign the hash with the private key
  const signature = ecdsaSuite.sign(privateKeyHex, messageHash);
  console.log('Signature:', signature);

  // 5. Verify the signature with the (validated) public key
  const isSignatureValid = ecdsaSuite.verify(signature, messageHash, compressedPubKey);
  console.log('Is the signature valid?', isSignatureValid); // true

} catch (error) {
  if (error instanceof KeyValidationError) {
    console.error('Validation Error:', error.message);
  } else {
    console.error('An unexpected error occurred:', error);
  }
}
```

## API Reference

### `getCryptoSuite(params)`

This is the main factory function of the library. It returns a complete "suite" of tools for a specific cryptographic system.

-   `params`: An object with the following properties:
    -   `curve: SupportedCurve`: The cryptographic curve to use.
    -   `scheme: SupportedScheme`: The algorithm/scheme to use.
-   **Returns:** An `ICryptoSuite` object containing methods for validation and cryptographic operations.
-   **Throws:** `KeyValidationError` if the requested `curve` and `scheme` combination is not supported.

#### Supported Combinations

| Curve         | Scheme  | Supported |
| :------------ | :------ | :-------- |
| `secp256k1`   | `ECDSA` | ✅         |
| `secp256k1`   | `Schnorr` | ✅         |
| `ed25519`     | `EdDSA` | ✅         |

### The `ICryptoSuite` Interface

This is the object returned by `getCryptoSuite`. It contains the following methods:

#### `suite.validateAndNormalizePublicKey(pubKeyHex, [options])`

Validates and normalizes a public key according to the rules of the selected suite.

-   `pubKeyHex: string`: The public key as a hex string.
-   `options?: { outputFormat?: PublicKeyFormat }`: (Optional) An object to specify the desired output format.
    -   This is only applicable to `secp256k1` with `ECDSA`. It is ignored by other suites which have a single, fixed public key format.
    -   Defaults to `'compressed'` if not provided.
-   **Returns:** An object `{ publicKey: string; format: PublicKeyFormat }`.
-   **Throws:** `KeyValidationError` if the public key is invalid for the suite (e.g., wrong length, invalid point).

#### `suite.sign(privateKeyHex, messageHash)`

Signs a message hash using the suite's algorithm.

-   `privateKeyHex: string`: The private key as a 32-byte hex string.
-   `messageHash: string`: The **hash** of the message to sign, as a hex string.
-   **Returns:** `string` - The signature in hexadecimal format.

#### `suite.verify(signature, messageHash, publicKey)`

Verifies a signature against a message hash and public key.

-   `signature: string`: The signature as a hex string.
-   `messageHash: string`: The **hash** of the message that was signed.
-   `publicKey: string`: The public key to use for verification. It should be in the format expected by the suite (e.g., compressed for ECDSA).
-   **Returns:** `boolean` - `true` if the signature is valid, `false` otherwise.

### Exported Types

You can import these types for strong type-safety in your project.

-   **`SupportedCurve`**: `'secp256k1' | 'ed25519'`
-   **`SupportedScheme`**: `'ECDSA' | 'Schnorr' | 'EdDSA'`
-   **`PublicKeyFormat`**: `'compressed' | 'uncompressed' | 'schnorr'`
-   **`ICryptoSuite`**: The interface for the returned suite object.
-   **`KeyValidationError`**: The custom error class thrown by the library.

## Contributing

Contributions, issues, and feature requests are welcome! Feel free to check the [issues page](https://github.com/colossusdigital/cryptoSuiteKit/issues).

## License

This project is [MIT](https://opensource.org/licenses/MIT) licensed.

Copyright © 2025 Colossus S.R.L.
