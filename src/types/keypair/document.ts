import type { VerificationMethodMap } from "@crumble-jon/ld-crypto-syntax"

/**
 * A JSON-LD document that represents an Ed25519 keypair.
 */
export interface KeypairDocument extends VerificationMethodMap {
  /**
   * The `privateKeyMultibase` property is used to express a private key in multibase format.
   *
   * The value of this property MUST be a string representation of a multibase encoded private key.
   *
   * @see https://datatracker.ietf.org/doc/html/draft-multiformats-multibase-03
   */
  privateKeyMultibase?: string
}
