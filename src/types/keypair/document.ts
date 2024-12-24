import type { DIDURL, PlainDocument } from "@crumble-jon/ld-crypto-syntax"

/**
 * A set of data describing a keypair, such as a cryptographic keypair, that can be used to authenticate a verifiable
 * credential.
 */
export interface KeypairDocument extends PlainDocument {
  /**
   * The identifier for a particular keypair.
   *
   * The value of this property MUST be a string that conforms to the DID URL syntax.
   */
  id: DIDURL

  /**
   * The `controller` property is used to express the entity that controls the corresponding private key.
   *
   * The value of this property MUST be a string that conforms to the DID syntax.
   */
  controller: DIDURL

  /**
   * The `type` property is used to express the type of keypair.
   *
   * The value of this property MUST be a string that references exactly one keypair type.
   */
  type: string

  /**
   * The `revoked` property is used to express the date and time at which the keypair was revoked.
   * 
   * The value of this property MUST be a string that conforms to the W3C `dateTime` format.
   */
  revoked?: string

  /**
   * The `publicKeyMultibase` property is used to express a public key in multibase format.
   *
   * The value of this property MUST be a string representation of a multibase encoded public key.
   *
   * @see https://datatracker.ietf.org/doc/html/draft-multiformats-multibase-03
   */
  publicKeyMultibase?: string

  /**
   * The `privateKeyMultibase` property is used to express a private key in multibase format.
   *
   * The value of this property MUST be a string representation of a multibase encoded private key.
   *
   * @see https://datatracker.ietf.org/doc/html/draft-multiformats-multibase-03
   */
  privateKeyMultibase?: string
}
