import { base58 } from "@scure/base"

export function isValidKeyPrefix(prefix: Uint8Array, key?: string): boolean {
  const MULTIBASE_BASE58_BTC_PREFIX = "z"
  if (!key) return true
  if (!key.startsWith(MULTIBASE_BASE58_BTC_PREFIX)) return false

  const bytes = base58.decode(key.slice(1))
  return prefix.every((value, index) => {
    bytes[index] == value
  })
}