import {
  type CIDDocument,
  type DIDURL,
  document,
  ImplementationError,
  ImplementationErrorCode,
  Keypair,
  type KeypairOptions,
  loader,
  type URI,
  VC_BASE_URL,
  type VerificationMethodJwk,
  type VerificationMethodMultibase,
  type VerificationRelationship,
} from "@herculas/vc-data-integrity"

import * as core from "../utils/key.ts"
import * as SUITE_CONSTANT from "../constant/suite.ts"

/**
 * The Ed25519 keypair class. The secret key is a scalar, and the public key is a point on the Ed25519 curve.
 */
export class Ed25519Keypair extends Keypair {
  /**
   * The Ed25519 public key.
   */
  publicKey?: CryptoKey

  /**
   * The Ed25519 private key.
   */
  privateKey?: CryptoKey

  /**
   * The type of the cryptographic suite used by the keypair instances.
   */
  static override readonly type = SUITE_CONSTANT.KEYPAIR_TYPE

  /**
   * @param {URI} [_id] The identifier of the keypair.
   * @param {DIDURL} [_controller] The controller of the keypair.
   * @param {Date} [_revoked] The date and time when the keypair has been revoked.
   */
  constructor(_id?: URI, _controller?: DIDURL, _revoked?: Date) {
    super(_id, _controller, _revoked)
    // TODO: add expiration date
  }

  /**
   * Initialize the Ed25519 keypair using the Web Crypto API, set the public and private key material encoded in
   * multibase format.
   */
  override async initialize() {
    const keypair = await core.generateRawKeypair()
    this.privateKey = keypair.privateKey
    this.publicKey = keypair.publicKey

    // set identifier if controller is provided
    if (this.controller && !this.id) {
      this.id = `${this.controller}#${await this.generateFingerprint()}`
    }
  }

  /**
   * Calculate the public key fingerprint, multibase + multicodec encoded. The specific fingerprint method is determined
   * by the key suite, and is often either a hash of the public key material, or the full encoded public key. This
   * method is frequently used to initialize the key identifier or generate some types of cryptonym DIDs.
   *
   * @returns {Promise<string>} Resolve to the fingerprint.
   */
  override async generateFingerprint(): Promise<string> {
    if (!this.publicKey) {
      throw new ImplementationError(
        ImplementationErrorCode.INVALID_KEYPAIR_CONTENT,
        "Ed25519Keypair.generateFingerprint",
        "Public key has not been generated!",
      )
    }
    const material = await core.keyToMaterial(this.publicKey, "public")
    return core.materialToMultibase(material, "public")
  }

  /**
   * Verify that a provided fingerprint matches the public key material belonging to this keypair.
   *
   * @param {string} fingerprint A public key fingerprint.
   *
   * @returns {Promise<boolean>} Resolve to a boolean indicating whether the given fingerprint matches this keypair
   * instance.
   */
  override async verifyFingerprint(fingerprint: string): Promise<boolean> {
    return fingerprint === await this.generateFingerprint()
  }

  /**
   * Export the serialized representation of the keypair, along with other metadata which can be used to form a proof.
   *
   * @param {KeypairOptions.Export} options The options to export the keypair.
   *
   * @returns {Promise<CIDDocument>} Resolve to a serialized keypair to be exported.
   */
  override async export(options?: KeypairOptions.Export): Promise<CIDDocument> {
    // set default options
    options ||= {}
    options.flag ||= "public"
    options.type ||= SUITE_CONSTANT.KEYPAIR_DOCUMENT_TYPE_MULTI

    // check if the keypair has been initialized
    if ((options.flag === "private" && !this.privateKey) || (options.flag === "public" && !this.publicKey)) {
      throw new ImplementationError(
        ImplementationErrorCode.KEYPAIR_EXPORT_ERROR,
        "Ed25519Keypair.export",
        "This keypair has not been initialized!",
      )
    }

    // check if the identifier and controller are well-formed
    if (!this.id || !this.controller || !this.id.startsWith(this.controller)) {
      throw new ImplementationError(
        ImplementationErrorCode.KEYPAIR_EXPORT_ERROR,
        "Ed25519Keypair.export",
        "The identifier or controller of this keypair is not well-formed!",
      )
    }

    // initialize the exported document
    const document: CIDDocument = {
      "@context": VC_BASE_URL.CID_V1,
      id: this.controller,
      verificationMethod: [],
    }

    // generate the verification method
    if (options.type === SUITE_CONSTANT.KEYPAIR_DOCUMENT_TYPE_MULTI) {
      const verificationMethod = await core.keypairToMultibase(this, options.flag)
      document.verificationMethod!.push(verificationMethod)
    } else if (options.type === SUITE_CONSTANT.KEYPAIR_DOCUMENT_TYPE_JWK) {
      const verificationMethod = await core.keypairToJwk(this, options.flag)
      document.verificationMethod!.push(verificationMethod)
    } else {
      throw new ImplementationError(
        ImplementationErrorCode.KEYPAIR_EXPORT_ERROR,
        "Ed25519Keypair.export",
        "The keypair type is not supported!",
      )
    }

    // iterate through the verification relationships in the export option
    for (const relationshipName in options.relationship) {
      document[relationshipName] = new Array<VerificationRelationship>()
      document[relationshipName].push(document.verificationMethod![0].id)
    }

    // return the exported document
    return document
  }

  /**
   * Import a keypair from a serialized representation of a keypair.
   *
   * @param {CIDDocument} inputDocument A keypair document fetched from a external source.
   * @param {KeypairOptions.Import} options Options for keypair import.
   *
   * @returns {Promise<Ed25519Keypair>} Resolve to a Ed25519 keypair instance.
   */
  static override async import(inputDocument: CIDDocument, options?: KeypairOptions.Import): Promise<Ed25519Keypair> {
    // set default options
    options ||= {}
    options.checkContext ||= true
    options.checkRevoked ||= false

    // validate the JSON-LD context
    // TODO: the default document loader should not invoke any network requests
    if (options.checkContext) {
      const res = await document.validateContext(inputDocument, VC_BASE_URL.CID_V1, false, loader.fallback)
      if (!res.validated) {
        throw new ImplementationError(
          ImplementationErrorCode.INVALID_KEYPAIR_CONTENT,
          "Ed25519Keypair#import",
          "The JSON-LD context is not supported by this application!",
        )
      }
    }

    // load the verification method from the controlled identifier document
    // TODO: methods should be chosen based on the given fragment identifier
    const method = inputDocument.verificationMethod?.[0]
    if (!method) {
      throw new ImplementationError(
        ImplementationErrorCode.INVALID_KEYPAIR_CONTENT,
        "Ed25519Keypair#import",
        "The verification method is missing from the input controlled identifier document!",
      )
    }

    // check the revocation status
    // TODO: should also check the expiration status
    const revoked = method.revoked ? new Date(method.revoked) : undefined
    if (options.checkRevoked) {
      if (revoked && revoked < new Date()) {
        throw new ImplementationError(
          ImplementationErrorCode.KEYPAIR_EXPIRED_ERROR,
          "Ed25519Keypair#import",
          "The keypair represented by the verification method has been revoked!",
        )
      }
    }

    // import the keypair from the verification method
    if (method.type === SUITE_CONSTANT.KEYPAIR_DOCUMENT_TYPE_MULTI) {
      return core.multibaseToKeypair(method as VerificationMethodMultibase, revoked)
    } else if (method.type === SUITE_CONSTANT.KEYPAIR_DOCUMENT_TYPE_JWK) {
      return core.jwkToKeypair(method as VerificationMethodJwk, revoked)
    } else {
      throw new ImplementationError(
        ImplementationErrorCode.KEYPAIR_IMPORT_ERROR,
        "Ed25519Keypair#import",
        "The keypair type is not supported!",
      )
    }
  }
}
