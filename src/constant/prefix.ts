/**
 * The encoding of an Ed25519 public key MUST start with the two-byte prefix `0xed01` (the varint expression of `0xed`),
 * followed by the 32-byte public key data.
 *
 * The resulting 34-byte value MUST be encoded using the base-58-btc alphabet, and then prepended with the base-58-btc
 * Multibase header `z`.
 *
 * @see https://www.w3.org/TR/cid/#Multikey
 */
export const PUBLIC_KEY_MULTIBASE = "ed01"

/**
 * The encoding of an Ed25519 secret key MUST start with the two-byte prefix `0x8026` (the varint expression of
 * `0x1300`), followed by the 32-byte secret key data.
 *
 * The resulting 34-byte value MUST be encoded using the base-58-btc alphabet, and then prepended with the base-58-btc
 * Multibase header `z`.
 *
 * @see https://www.w3.org/TR/cid/#Multikey
 */
export const PRIVATE_KEY_MULTIBASE = "8026"

/**
 * The DER prefix for an Ed25519 public key, which could be decomposed as follows:
 *
 * - `302a`: `SEQUENCE` (42 bytes in total)
 * - `3005`: `SEQUENCE` (5 bytes following)
 * - `0603 2b6570`: `Object Identifier` (3 bytes, with content of 1.3.101.112, representing Ed25519)
 * - `0321`: `BIT STRING` (33 bytes following, a byte for version and 32 bytes for public key)
 * - `00`: Version 0
 */
export const PUBLIC_KEY_DER = "302a300506032b6570032100"

/**
 * The DER prefix for an Ed25519 private key, which could be decomposed as follows:
 *
 * - `302e`: `SEQUENCE` (46 bytes in total)
 * - `020100`: `INTEGER` (1 byte for version, with value of 0x0)
 * - `3005`: `SEQUENCE` (5 bytes following)
 * - `0603 2b6570`: `Object Identifier` (3 bytes, with content of 1.3.101.112, representing Ed25519)
 * - `0422`: `OCTET STRING` (34 bytes following)
 * - `0420`: `OCTET STRING` (32 bytes following, representing the private key)
 */
export const PRIVATE_KEY_DER = "302e020100300506032b657004220420"
