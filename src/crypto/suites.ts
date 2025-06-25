import { bytesToHex } from '@noble/curves/abstract/utils';
import { ed25519 } from '@noble/curves/ed25519';
import { secp256k1, schnorr } from '@noble/curves/secp256k1';
import { KeyValidationError } from '../errors/KeyValidationError';

// --- PUBLIC TYPES ---

export type SupportedCurve = 'secp256k1' | 'ed25519';
export type SupportedScheme = 'ECDSA' | 'Schnorr' | 'EdDSA';
export type PublicKeyFormat = 'compressed' | 'uncompressed' | 'schnorr';

/**
 * Defines a complete suite of cryptographic tools for a specific
 * combination of curve and scheme.
 */
export interface ICryptoSuite {
  /**
   * Validates and normalizes a public key according to the suite's specific rules.
   * @param pubKeyHex The public key to validate.
   * @param options Options for the validation, such as the desired output format.
   * @returns A normalized version of the public key.
   */
  validateAndNormalizePublicKey(
    pubKeyHex: string,
    options?: { outputFormat?: PublicKeyFormat }
  ): { publicKey: string; format: PublicKeyFormat };

  /**
   * Signs a message digest with a private key.
   * @param privateKey The private key as a hex string.
   * @param messageHash The hash of the message to sign, as a hex string.
   * @returns The signature as a hex string.
   */
  sign(privateKey: string, messageHash: string): string;

  /**
   * Verifies a signature.
   * @param signature The signature as a hex string.
   * @param messageHash The hash of the message that was signed, as a hex string.
   * @param publicKey The public key to use for verification.
   * @returns `true` if the signature is valid, `false` otherwise.
   */
  verify(signature: string, messageHash: string, publicKey: string): boolean;
}

// --- SUITE IMPLEMENTATIONS ---

const EcdsaSecp256k1Suite: ICryptoSuite = {
  validateAndNormalizePublicKey(
    pubKeyHex: string,
    options?: { outputFormat?: PublicKeyFormat }
  ) {
    let inputFormat: PublicKeyFormat | undefined;
    if (
      pubKeyHex.length === 66 &&
      (pubKeyHex.startsWith('02') || pubKeyHex.startsWith('03'))
    ) {
      inputFormat = 'compressed';
    } else if (
      pubKeyHex.length === 128 ||
      (pubKeyHex.length === 130 && pubKeyHex.startsWith('04'))
    ) {
      inputFormat = 'uncompressed';
    }
    if (!inputFormat) {
      throw new KeyValidationError(
        'Invalid ECDSA public key format. Expected 33 or 65 bytes.'
      );
    }

    // Default to 'compressed' if no output format is specified
    const desiredFormat = options?.outputFormat || 'compressed';
    const shouldCompress = desiredFormat === 'compressed';

    const point = secp256k1.Point.fromHex(
      inputFormat === 'uncompressed' && pubKeyHex.length === 128
        ? '04' + pubKeyHex
        : pubKeyHex
    );

    return {
      publicKey: bytesToHex(point.toBytes(shouldCompress)),
      format: desiredFormat,
    };
  },
  sign(privateKey: string, messageHash: string): string {
    return secp256k1.sign(messageHash, privateKey).toCompactHex();
  },
  verify(signature: string, messageHash: string, publicKey: string): boolean {
    return secp256k1.verify(signature, messageHash, publicKey);
  },
};

const SchnorrSecp256k1Suite: ICryptoSuite = {
  validateAndNormalizePublicKey(pubKeyHex: string) {
    // The 'outputFormat' option is ignored for this suite as it only has one standard format.
    if (pubKeyHex.length !== 64) {
      throw new KeyValidationError(
        `Invalid Schnorr (BIP340) public key length. Expected 32 bytes (64 hex chars), got ${pubKeyHex.length}.`
      );
    }
    return { publicKey: pubKeyHex, format: 'schnorr' };
  },
  sign(privateKey: string, messageHash: string): string {
    return bytesToHex(schnorr.sign(messageHash, privateKey));
  },
  verify(signature: string, messageHash: string, publicKey: string): boolean {
    return schnorr.verify(signature, messageHash, publicKey);
  },
};

const EddsaEd25519Suite: ICryptoSuite = {
  validateAndNormalizePublicKey(pubKeyHex: string) {
    // The 'outputFormat' option is also ignored for Ed25519 as it has a single standard format.
    if (pubKeyHex.length !== 64) {
      throw new KeyValidationError(
        `Invalid EdDSA (Ed25519) public key length. Expected 32 bytes (64 hex chars), got ${pubKeyHex.length}.`
      );
    }
    try {
      ed25519.Point.fromHex(pubKeyHex);
    } catch (e) {
      throw new KeyValidationError(
        'Invalid Ed25519 public key. Not a valid point on the curve.'
      );
    }
    return { publicKey: pubKeyHex, format: 'compressed' };
  },
  sign(privateKey: string, messageHash: string): string {
    const signatureBytes = ed25519.sign(messageHash, privateKey);
    return bytesToHex(signatureBytes);
  },
  verify(signature: string, messageHash: string, publicKey: string): boolean {
    return ed25519.verify(signature, messageHash, publicKey);
  },
};

// --- FACTORY ---

const cryptoSuites: Record<
  SupportedCurve,
  Partial<Record<SupportedScheme, ICryptoSuite>>
> = {
  secp256k1: {
    ECDSA: EcdsaSecp256k1Suite,
    Schnorr: SchnorrSecp256k1Suite,
  },
  ed25519: {
    EdDSA: EddsaEd25519Suite,
  },
};

/**
 * Gets a complete cryptographic suite for a given curve and scheme.
 *
 * @param params An object containing the desired curve and scheme.
 * @returns An `ICryptoSuite` object with `validateAndNormalizePublicKey`, `sign`, and `verify` methods.
 * @throws {KeyValidationError} if the curve/scheme combination is not supported.
 */
export function getCryptoSuite(params: {
  curve: SupportedCurve;
  scheme: SupportedScheme;
}): ICryptoSuite {
  const suite = cryptoSuites[params.curve]?.[params.scheme];
  if (!suite) {
    throw new KeyValidationError(
      `The scheme '${params.scheme}' is not supported for the curve '${params.curve}'.`
    );
  }
  return suite;
}