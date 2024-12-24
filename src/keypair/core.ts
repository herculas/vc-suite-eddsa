import { base58 } from "@scure/base"
import * as CONSTANTS from "./constants.ts"

/**
 * Generate a raw keypair using the Web Crypto API.
 *
 * @returns {Promise<{ privateKey: Uint8Array; publicKey: Uint8Array }>} Resolve to the generated keypair.
 */
export async function generateRawKeypair(): Promise<{ privateKey: Uint8Array; publicKey: Uint8Array }> {
  const keypair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]) as CryptoKeyPair
  const privateKey = await crypto.subtle.exportKey("pkcs8", keypair.privateKey)
  const publicKey = await crypto.subtle.exportKey("spki", keypair.publicKey)

  const privateMaterial = getKeyMaterial(privateKey, "private")
  const publicMaterial = getKeyMaterial(publicKey, "public")

  return {
    privateKey: privateMaterial,
    publicKey: publicMaterial,
  }
}

/**
 * Get the key material from a DER-encoded key object.
 *
 * @param {ArrayBuffer} key The DER-encoded key object.
 * @param {string} flag The flag to determine if the key is private or public.
 * @returns {Uint8Array} The key material.
 */
export function getKeyMaterial(key: ArrayBuffer, flag: "private" | "public"): Uint8Array {
  if (flag === "private") {
    const prefix = new Uint8Array(key.slice(0, 16))
    if (!prefix.every((value, index) => value === CONSTANTS.DER_PRIVATE_KEY_PREFIX[index])) {
      throw new Error("Expected the buffer to be a ED25519 private key!")
    }
    return new Uint8Array(key.slice(16))
  } else if (flag === "public") {
    const prefix = new Uint8Array(key.slice(0, 12))
    if (!prefix.every((value, index) => value === CONSTANTS.DER_PUBLIC_KEY_PREFIX[index])) {
      throw new Error("Expected the buffer to be a ED25519 public key!")
    }
    return new Uint8Array(key.slice(12))
  }
  throw new Error("Invalid flag!")
}

export function assertKeyPrefix(key: string, prefix: Uint8Array) {
  decodeMultibase(key, prefix)
}

export function encodeMultibase(key: Uint8Array, prefix: Uint8Array): string {
  const multibase = new Uint8Array(prefix.length + key.length)
  multibase.set(prefix)
  multibase.set(key, prefix.length)
  return CONSTANTS.MULTIBASE_BASE58_BTC_PREFIX + base58.encode(multibase)
}

export function decodeMultibase(multibase: string, prefix?: Uint8Array): Uint8Array {
  if (!multibase.startsWith(CONSTANTS.MULTIBASE_BASE58_BTC_PREFIX)) {
    throw new Error("Invalid multibase prefix!")
  }
  const key = base58.decode(multibase.slice(1))
  if (prefix) {
    prefix.forEach((value, index) => {
      if (key[index] != value) {
        throw new Error("Invalid key prefix!")
      }
    })
  }
  return key
}

// export function encodeMultibaseKey(prefix: Uint8Array, key: Uint8Array): string {
//   const multibaseKey = new Uint8Array(prefix.length + key.length)
//   multibaseKey.set(prefix)
//   multibaseKey.set(key, prefix.length)
//   return MULTIBASE_BASE58_BTC_PREFIX + base58.encode(multibaseKey)
// }

// export function isValidKeyPrefix(prefix: Uint8Array, key?: string): boolean {
//   if (!key) return true
//   if (!key.startsWith(MULTIBASE_BASE58_BTC_PREFIX)) return false
//   const bytes = base58.decode(key.slice(1))
//   prefix.forEach((value, index) => {
//     if (bytes[index] != value) {
//       return false
//     }
//   })
//   return true
// }
