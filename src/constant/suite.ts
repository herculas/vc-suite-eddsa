import type { KeypairOptions } from "@herculas/vc-data-integrity"

export const JWK_TYPE = "OKP"
export const JWK_USE = "sig"
export const ALGORITHM = "Ed25519"

export const KEYPAIR_TYPE = "Ed25519VerificationKey2020"
export const GENERAL_PROOF_TYPE = "DataIntegrityProof"

export const KEYPAIR_DOCUMENT_TYPE_MULTI = "Multikey"
export const KEYPAIR_DOCUMENT_TYPE_JWK = "JsonWebKey"

export const SUITE_RDFC = "eddsa-rdfc-2022"
export const SUITE_JCS = "eddsa-jcs-2022"

export const KEY_FORMAT: Map<KeypairOptions.Flag, "pkcs8" | "spki"> = new Map([
  ["public", "spki"],
  ["private", "pkcs8"],
])

export const KEY_MATERIAL_LENGTH: Map<KeypairOptions.Flag, number> = new Map([
  ["public", 32],
  ["private", 32],
])
