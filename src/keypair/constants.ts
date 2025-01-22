export const TYPE_BASIC = "Ed25519VerificationKey2020"
export const TYPE_JWK = "JsonWebKey2020"

export const PUBLIC_FORMAT = "spki"
export const PRIVATE_FORMAT = "pkcs8"

export const JWK_DEFAULT_TYPE = "OKP"
export const JWK_DEFAULT_USE = "sig"

export const MULTIBASE_BASE58_BTC_PREFIX = "z"

export const MULTIBASE_PUBLIC_PREFIX = new Uint8Array([0xed, 0x01])
export const MULTIBASE_PRIVATE_PREFIX = new Uint8Array([0x80, 0x26])

export const LENGTH_PRIVATE_KEY = 64
export const LENGTH_PUBLIC_KEY = 32

export const DER_PUBLIC_PREFIX = new Uint8Array([
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

export const DER_PRIVATE_PREFIX = new Uint8Array([
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


