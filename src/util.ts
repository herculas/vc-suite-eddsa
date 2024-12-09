import { base58 } from "@scure/base"

const MULTIBASE_BASE58_BTC_PREFIX = "z"

export function encodeMultibaseKey(prefix: Uint8Array, key: Uint8Array): string {
  const multibaseKey = new Uint8Array(prefix.length + key.length)
  multibaseKey.set(prefix)
  multibaseKey.set(key, prefix.length)
  return MULTIBASE_BASE58_BTC_PREFIX + base58.encode(multibaseKey)
}

export function isValidKeyPrefix(prefix: Uint8Array, key?: string): boolean {
  if (!key) return true
  if (!key.startsWith(MULTIBASE_BASE58_BTC_PREFIX)) return false

  const bytes = base58.decode(key.slice(1))

  prefix.forEach((value, index) => {
    if (bytes[index] != value) {
      return false
    }
  })

  return true
}