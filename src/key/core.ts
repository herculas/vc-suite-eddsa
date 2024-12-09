import { Buffer } from "node:buffer"
import { createPrivateKey, createPublicKey, randomBytes } from "node:crypto"

const DER_PRI_KEY_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex")
const DER_PUB_KEY_PREFIX = Buffer.from("302a300506032b6570032100", "hex")

/**
 * Generate a raw keypair using a 32-byte seed.
 *
 * @param {Uint8Array} seed A 32-byte seed.
 *
 * @returns {{ publicKey: Buffer; privateKey: Buffer }} The generated keypair.
 */
export function generateRawKeypair(seed?: Uint8Array): { publicKey: Buffer; privateKey: Buffer } {
  if (!seed) {
    seed = randomBytes(32)
  }
  const privateKey = createPrivateKey({
    key: _seedDerEncode(seed),
    format: "der",
    type: "pkcs8",
  })
  const publicKey = createPublicKey(privateKey)
  const publicKeyBuffer = publicKey.export({ format: "der", type: "spki" })
  const publicKeyBytes = _getKeyMaterial(publicKeyBuffer)
  return {
    publicKey: publicKeyBytes,
    privateKey: Buffer.concat([seed, publicKeyBytes]),
  }
}

/**
 * Encode a seed as a DER-encoded private key.
 *
 * @param {Uint8Array|Buffer} seed A 32-byte seed.
 *
 * @returns {Buffer} The DER-encoded private key.
 */
function _seedDerEncode(seed: Uint8Array | Buffer): Buffer {
  if (seed.length !== 32) {
    throw new Error("Invalid seed length!")
  }
  return Buffer.concat([DER_PRI_KEY_PREFIX, seed])
}

/**
 * Get the key material from a key buffer. The key material is the part of the buffer after the DER Prefix.
 *
 * @param {Buffer} keyBuffer A DER-encoded key buffer.
 *
 * @returns {Buffer} The key material part of the buffer.
 */
function _getKeyMaterial(keyBuffer: Buffer): Buffer {
  if (keyBuffer.indexOf(DER_PUB_KEY_PREFIX) === 0) {
    return keyBuffer.subarray(DER_PUB_KEY_PREFIX.length, keyBuffer.length)
  }
  if (keyBuffer.indexOf(DER_PRI_KEY_PREFIX) === 0) {
    return keyBuffer.subarray(DER_PRI_KEY_PREFIX.length, keyBuffer.length)
  }
  throw new Error("Expected the buffer to be a ED25519 public or private key!")
}
