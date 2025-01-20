import {
  concatenate,
  type DIDURL,
  type JWKEC,
  Keypair,
  type KeypairDocument,
  type KeypairExportOptions,
  type KeypairImportOptions,
  toW3CTimestampString,
  type URI,
  type VerificationResult,
} from "@crumble-jon/ld-crypto-syntax"

import * as CONTEXT_URL from "../context/constants.ts"
import * as KEYPAIR_CONSTANT from "./constants.ts"
import {
  generateKeypair,
  getJwkThumbprint,
  keyToJwk,
  keyToMaterial,
  materialToKey,
  materialToMultibase,
  multibaseToMaterial,
} from "./core.ts"
import { jwkToKey } from "./core.ts"
import { SuiteError } from "../error/error.ts"
import { SuiteErrorCode } from "../error/constants.ts"

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
   * @param {URI} [_id] The identifier of the keypair.
   * @param {DIDURL} [_controller] The controller of the keypair.
   * @param {Date} [_revoked] The date and time when the keypair has been revoked.
   */
  constructor(
    _id?: URI,
    _controller?: DIDURL,
    _revoked?: Date,
  ) {
    super(KEYPAIR_CONSTANT.TYPE_BASIC, _id, _controller, _revoked)
  }

  /**
   * Initialize the Ed25519 keypair using the Web Crypto API, set the public and private key material encoded in
   * multibase format.
   */
  override async initialize() {
    const keypair = await generateKeypair()
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
  override generateFingerprint(): Promise<string> {
    return this.getPublicKeyMultibase()
  }

  /**
   * Verify that a provided fingerprint matches the public key material belonging to this keypair.
   *
   * @param {string} fingerprint A public key fingerprint.
   *
   * @returns {Promise<VerificationResult>} Resolve to a boolean indicating whether the given fingerprint matches this
   * keypair instance.
   */
  override async verifyFingerprint(fingerprint: string): Promise<VerificationResult> {
    if (fingerprint !== await this.generateFingerprint()) {
      return Promise.resolve({
        verified: false,
        errors: new SuiteError(
          SuiteErrorCode.FINGERPRINT_VERIFICATION_FAILURE,
          "Ed25519Keypair.verifyFingerprint",
          "Fingerprint does not match!",
        ),
      })
    }
    return Promise.resolve({
      verified: true,
    })
  }

  /**
   * Export the serialized representation of the keypair, along with other metadata which can be used to form a proof.
   *
   * @param {KeypairExportOptions} options The options to export the keypair.
   *
   * @returns {Promise<KeypairDocument>} Resolve to a serialized keypair to be exported.
   */
  override async export(options: KeypairExportOptions): Promise<KeypairDocument> {
    if (!options.flag) {
      options.flag = "public"
    }
    if ((options.flag === "private" && !this.privateKey) || (options.flag === "public" && !this.publicKey)) {
      throw new SuiteError(
        SuiteErrorCode.LOGIC_ERROR,
        "Ed25519Keypair.export",
        "This keypair has not been initialized!",
      )
    }
    if (!this.id || !this.controller) {
      throw new SuiteError(
        SuiteErrorCode.LOGIC_ERROR,
        "Ed25519Keypair.export",
        "Required fields are missing!",
      )
    }

    const result: KeypairDocument = {
      "@context": CONTEXT_URL.SUITE_2020,
      id: this.id,
      controller: this.controller,
      type: this.type,
      revoked: this.revoked ? toW3CTimestampString(this.revoked) : undefined,
    }

    if (options.type === "jwk") {
      if (options.flag === "public") {
        result.publicKeyJwk = await keyToJwk(this.publicKey!, "public")
      } else if (options.flag === "private") {
        result.publicKeyJwk = await keyToJwk(this.privateKey!, "private")
      }
      result["@context"] = CONTEXT_URL.JWS_2020
      result.type = KEYPAIR_CONSTANT.TYPE_JWK
      result.id = `${this.controller}#${await getJwkThumbprint(result.publicKeyJwk!)}`
    } else if (options.type === "multibase") {
      result.publicKeyMultibase = await this.getPublicKeyMultibase()
      if (options.flag === "private") {
        result.secretKeyMultibase = await this.getPrivateKeyMultibase()
      }
    } else {
      throw new SuiteError(
        SuiteErrorCode.LOGIC_ERROR,
        "Ed25519Keypair.export",
        "Unsupported export type!",
      )
    }

    // TODO: remove all undefined fields
    return result
  }

  /**
   * Import a keypair from a serialized representation of a keypair.
   *
   * @param {KeypairDocument} document An externally fetched key document.
   * @param {KeypairImportOptions} options Options for keypair import.
   *
   * @returns {Promise<Ed25519Keypair>} Resolve to a keypair instance.
   */
  static override async import(document: KeypairDocument, options: KeypairImportOptions): Promise<Ed25519Keypair> {
    // check the context
    if (document["@context"] && options.checkContext && document["@context"] !== CONTEXT_URL.SUITE_2020) {
      throw new SuiteError(
        SuiteErrorCode.FORMAT_ERROR,
        "Ed25519Keypair.import",
        "The context is not supported!",
      )
    }

    // check the document type
    if (document.type !== KEYPAIR_CONSTANT.TYPE_BASIC && document.type !== KEYPAIR_CONSTANT.TYPE_JWK) {
      throw new SuiteError(
        SuiteErrorCode.FORMAT_ERROR,
        "Ed25519Keypair.import",
        "The keypair type is not supported!",
      )
    }

    // check if the keypair has been revoked
    const revoked = document.revoked ? new Date(document.revoked) : undefined
    if (revoked && options.checkRevoked && revoked < new Date()) {
      throw new SuiteError(
        SuiteErrorCode.EXPIRED_KEYPAIR,
        "Ed25519Keypair.import",
        "The keypair has been revoked!",
      )
    }

    const keypair = new Ed25519Keypair(document.id, document.controller, revoked)

    if (options.type === "jwk") {
      if (!document.publicKeyJwk) {
        throw new SuiteError(
          SuiteErrorCode.DECODING_ERROR,
          "Ed25519Keypair.import",
          "The key material is missing from the JWK object!",
        )
      }
      const jwk = document.publicKeyJwk as JWKEC

      if (jwk.d) {
        // private key
        const jwkCopy = { ...jwk }
        delete jwkCopy.d
        jwkCopy.key_ops = ["verify"]
        keypair.privateKey = await jwkToKey(jwk, "private")
        keypair.publicKey = await jwkToKey(jwkCopy, "public")
      } else {
        // public key only
        keypair.publicKey = await jwkToKey(jwk, "public")
      }
    } else if (options.type === "multibase") {
      if (document.secretKeyMultibase) {
        // private key
        const combinedMaterial = multibaseToMaterial(document.secretKeyMultibase, "private")
        const privateKeyMaterial = combinedMaterial.slice(0, 32)
        const publicKeyMaterial = combinedMaterial.slice(32)
        keypair.privateKey = await materialToKey(privateKeyMaterial, "private")
        keypair.publicKey = await materialToKey(publicKeyMaterial, "public")
      } else {
        // public key only
        const publicKeyMaterial = multibaseToMaterial(document.publicKeyMultibase!, "public")
        keypair.publicKey = await materialToKey(publicKeyMaterial, "public")
      }
    } else {
      throw new SuiteError(
        SuiteErrorCode.LOGIC_ERROR,
        "Ed25519Keypair.import",
        "Unsupported import type!",
      )
    }

    return keypair
  }

  /**
   * Calculate the public key multibase encoded string.
   *
   * @returns {Promise<string>} Resolve to the multibase encoded public key string.
   */
  private async getPublicKeyMultibase(): Promise<string> {
    if (!this.publicKey) {
      throw new SuiteError(
        SuiteErrorCode.LOGIC_ERROR,
        "Ed25519Keypair.getPublicKeyMultibase",
        "Public key has not been generated!",
      )
    }
    const material = await keyToMaterial(this.publicKey, "public")
    return materialToMultibase(material, "public")
  }

  /**
   * Calculate the private key multibase encoded string.
   *
   * @returns {Promise<string>} Resolve to the multibase encoded private key string.
   */
  private async getPrivateKeyMultibase(): Promise<string> {
    if (!this.privateKey || !this.publicKey) {
      throw new SuiteError(
        SuiteErrorCode.LOGIC_ERROR,
        "EW25519Keypair.getPrivateKeyMultibase",
        "Keypair has not been generated!",
      )
    }
    const skMaterial = await keyToMaterial(this.privateKey, "private")
    const pkMaterial = await keyToMaterial(this.publicKey, "public")
    const material = concatenate(skMaterial, pkMaterial)
    return materialToMultibase(material, "private")
  }
}
