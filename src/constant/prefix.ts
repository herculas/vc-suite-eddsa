/**
 * The encoding of an Ed25519 public key MUST start with the two-byte prefix `0xed01` (the varint expression of `0xed`),
 * followed by the 32-byte public key data.
 *
 * The resulting 34-byte value MUST be encoded using the base-58-btc alphabet, and then prepended with the base-58-btc
 * Multibase header `z`.
 *
 * @see https://www.w3.org/TR/cid/#Multikey
 */
export const PUBLIC_KEY_MULTIBASE = new Uint8Array([0xed, 0x01])

/**
 * The encoding of an Ed25519 secret key MUST start with the two-byte prefix `0x8026` (the varint expression of
 * `0x1300`), followed by the 32-byte secret key data.
 *
 * The resulting 34-byte value MUST be encoded using the base-58-btc alphabet, and then prepended with the base-58-btc
 * Multibase header `z`.
 *
 * @see https://www.w3.org/TR/cid/#Multikey
 */
export const PRIVATE_KEY_MULTIBASE = new Uint8Array([0x80, 0x26])

/**
 * The DER prefix for an Ed25519 public key, which could be decomposed as follows:
 *
 *    - `0x30 0x2a`: `SEQUENCE` of 42 bytes
 *        - `0x30 0x05`: `SEQUENCE` of 5 bytes
 *            - `0x06 0x03 0x2b6570`: `OID` of 3 bytes, 1.3.101.112 (Ed25519)
 *        - `0x03 0x21`: `BIT STRING` of 33 bytes
 *            - `0x00`: Padding byte
 *            - ... Public key contents of 32 bytes
 */
export const PUBLIC_KEY_DER = new Uint8Array([
  0x30,
  0x2a,
  0x30,
  0x05,
  0x06,
  0x03,
  0x2b,
  0x65,
  0x70,
  0x03,
  0x21,
  0x00,
])

/**
 * The DER prefix for an Ed25519 private key, which could be decomposed as follows:
 *
 *    - `0x30 0x2e`: `SEQUENCE` of 46 bytes
 *        - `0x02 0x01`: `INTEGER` of 1 byte
 *            - `0x00`: Padding byte
 *        - `0x30 0x05`: `SEQUENCE` of 5 bytes
 *            - `0x06 0x03 0x2b6570`: `OID` of 3 bytes, 1.3.101.112 (Ed25519)
 *        - `0x04 0x22`: `OCTET STRING` of 34 bytes
 *            - `0x04 0x20`: `OCTET STRING` of 32 bytes
 *                - ... Private key contents of 32 bytes
 */
export const PRIVATE_KEY_DER = new Uint8Array([
  0x30,
  0x2e,
  0x02,
  0x01,
  0x00,
  0x30,
  0x05,
  0x06,
  0x03,
  0x2b,
  0x65,
  0x70,
  0x04,
  0x22,
  0x04,
  0x20,
])
