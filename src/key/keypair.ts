import {
  type DIDURL,
  type ExportOptions,
  type ImportOptions,
  includeContext,
  type JWKEC,
  type KeyFlag,
  Keypair,
  toW3CTimestampString,
  type URI,
  VC_BASE_URL,
  type VerificationMethod,
  type VerificationMethodJwk,
  type VerificationMethodMultibase,
} from "@herculas/vc-data-integrity"
import * as CONTEXT_URL from "../context/url.ts"
import {
  generateKeypair,
  getJwkThumbprint,
  jwkToKey,
  keyToJwk,
  keyToMaterial,
  materialToKey,
  materialToMultibase,
  multibaseToMaterial,
} from "./core.ts"
import { SuiteError } from "../error/error.ts"
import { ErrorCode } from "../error/constants.ts"
import * as KEY_CONSTANT from "../constants/key.ts"

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
  constructor(_id?: URI, _controller?: DIDURL, _revoked?: Date) {
    super(KEY_CONSTANT.TYPE_BASIC, _id, _controller, _revoked)
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
  override async generateFingerprint(): Promise<string> {
    return await this.getPublicKeyMultibase()
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
   * @param {ExportOptions} options The options to export the keypair.
   *
   * @returns {Promise<KeypairDocument>} Resolve to a serialized keypair to be exported.
   */
  override export(options: ExportOptions): Promise<VerificationMethod> {
    if (!options.flag) {
      options.flag = "public"
    }

    if ((options.flag === "private" && !this.privateKey) || (options.flag === "public" && !this.publicKey)) {
      throw new SuiteError(
        ErrorCode.LOGIC_ERROR,
        "Ed25519Keypair.export",
        "This keypair has not been initialized!",
      )
    }

    if (!this.id || !this.controller) {
      throw new SuiteError(
        ErrorCode.LOGIC_ERROR,
        "Ed25519Keypair.export",
        "Required fields are missing!",
      )
    }

    if (options.type === "jwk") {
      return this.toJwk(options.flag)
    } else if (options.type === "multibase") {
      return this.toMultibase(options.flag)
    } else {
      throw new SuiteError(
        ErrorCode.LOGIC_ERROR,
        "Ed25519Keypair.export",
        "Unsupported export type!",
      )
    }
  }

  /**
   * Import a keypair from a serialized representation of a keypair.
   *
   * @param {KeypairDocument} document An externally fetched key document.
   * @param {ImportOptions} options Options for keypair import.
   *
   * @returns {Promise<Ed25519Keypair>} Resolve to a keypair instance.
   */
  static override import(document: VerificationMethod, options: ImportOptions): Promise<Ed25519Keypair> {
    // check the context
    if (options.checkContext) {
      if (!includeContext(document, [CONTEXT_URL.SUITE_2020, VC_BASE_URL.CID_V1])) {
        throw new SuiteError(
          ErrorCode.FORMAT_ERROR,
          "Ed25519Keypair.import",
          "The context is not supported!",
        )
      }
    }

    // check the type
    if (document.type !== KEY_CONSTANT.TYPE_BASIC && document.type !== KEY_CONSTANT.TYPE_JWK) {
      throw new SuiteError(
        ErrorCode.FORMAT_ERROR,
        "Ed25519Keypair.import",
        "The keypair type is not supported!",
      )
    }

    // check the revocation status
    const revoked = document.revoked ? new Date(document.revoked) : undefined
    if (revoked && options.checkRevoked && revoked < new Date()) {
      throw new SuiteError(
        ErrorCode.EXPIRED_KEYPAIR,
        "Ed25519Keypair.import",
        "The keypair has been revoked!",
      )
    }

    if (options.type === "jwk") {
      return Ed25519Keypair.fromJwk(document, revoked)
    } else if (options.type === "multibase") {
      return Ed25519Keypair.fromMultibase(document, revoked)
    } else {
      throw new SuiteError(
        ErrorCode.DECODING_ERROR,
        "Ed25519Keypair.import",
        "The key material is missing from the multibase object!",
      )
    }
  }

  /**
   * Calculate the multibase encoded public key.
   *
   * @returns {Promise<string>} Resolve to the multibase encoded public key string.
   */
  private async getPublicKeyMultibase(): Promise<string> {
    if (!this.publicKey) {
      throw new SuiteError(
        ErrorCode.LOGIC_ERROR,
        "Ed25519Keypair.getPublicKeyMultibase",
        "Public key has not been generated!",
      )
    }
    const material = await keyToMaterial(this.publicKey, "public")
    return materialToMultibase(material, "public")
  }

  /**
   * Calculate the multibase encoded private key.
   *
   * @returns {Promise<string>} Resolve to the multibase encoded private key string.
   */
  private async getPrivateKeyMultibase(): Promise<string> {
    if (!this.privateKey) {
      throw new SuiteError(
        ErrorCode.LOGIC_ERROR,
        "EW25519Keypair.getPrivateKeyMultibase",
        "Keypair has not been generated!",
      )
    }
    const material = await keyToMaterial(this.privateKey, "private")
    return materialToMultibase(material, "private")
  }

  /**
   * Export a keypair instance into a verification method containing a keypair in JWK format.
   *
   * @param {KeyFlag} flag The flag to determine if the key is private or public.
   *
   * @returns {Promise<VerificationMethodJwk>} Resolve to a verification method containing a keypair in JWK format.
   */
  private async toJwk(flag: KeyFlag): Promise<VerificationMethodJwk> {
    const document: VerificationMethodJwk = {
      id: this.id!,
      type: KEY_CONSTANT.TYPE_JWK,
      controller: this.controller!,
      revoked: this.revoked ? toW3CTimestampString(this.revoked) : undefined,
    }

    if (flag === "private") {
      document.secretKeyJwk = await keyToJwk(this.privateKey!, "private")
    }
    document.publicKeyJwk = await keyToJwk(this.publicKey!, "public")
    document.id = `${this.controller!}#${await getJwkThumbprint(document.publicKeyJwk)}`

    return document
  }

  /**
   * Export a keypair instance into a verification method containing a keypair in multibase format.
   *
   * @param {KeyFlag} flag The flag to determine if the key is private or public.
   *
   * @returns {Promise<VerificationMethodMultibase>} Resolve to a verification method containing a keypair in multibase
   * format.
   */
  private async toMultibase(flag: KeyFlag): Promise<VerificationMethodMultibase> {
    const document: VerificationMethodMultibase = {
      id: this.id!,
      type: this.type,
      controller: this.controller!,
      revoked: this.revoked ? toW3CTimestampString(this.revoked) : undefined,
    }

    if (flag === "private") {
      document.secretKeyMultibase = await this.getPrivateKeyMultibase()
    }
    document.publicKeyMultibase = await this.getPublicKeyMultibase()
    return document
  }

  /**
   * Import a keypair from a serialized verification method containing a keypair in JWK format.
   *
   * @param {VerificationMethodJwk} document An externally fetched key document.
   * @param {Date} revoked The revoked date of the keypair.
   *
   * @returns {Promise<Ed25519Keypair>} Resolve to a keypair instance.
   */
  private static async fromJwk(document: VerificationMethodJwk, revoked?: Date): Promise<Ed25519Keypair> {
    const keypair = new Ed25519Keypair(document.id, document.controller, revoked)

    // private key
    if (document.secretKeyJwk) {
      const jwk = document.secretKeyJwk as JWKEC
      keypair.privateKey = await jwkToKey(jwk, "private")
    }

    // public key
    if (document.publicKeyJwk) {
      const jwk = document.publicKeyJwk as JWKEC
      keypair.publicKey = await jwkToKey(jwk, "public")
    }

    // missing key material
    if (!document.secretKeyJwk && !document.publicKeyJwk) {
      throw new SuiteError(
        ErrorCode.DECODING_ERROR,
        "Ed25519Keypair.import",
        "The key material is missing from the JWK object!",
      )
    }

    return keypair
  }

  /**
   * Import a keypair from a serialized `KeypairDocument` object containing a keypair in multibase format.
   *
   * @param {VerificationMethodMultibase} document An externally fetched key document.
   * @param {Date} revoked The revoked date of the keypair.
   *
   * @returns {Promise<Ed25519Keypair>} Resolve to a keypair instance.
   */
  private static async fromMultibase(document: VerificationMethodMultibase, revoked?: Date): Promise<Ed25519Keypair> {
    const keypair = new Ed25519Keypair(document.id, document.controller, revoked)

    // private key
    if (document.secretKeyMultibase) {
      const material = multibaseToMaterial(document.secretKeyMultibase!, "private")
      keypair.privateKey = await materialToKey(material, "private")
    }

    // public key
    if (document.publicKeyMultibase) {
      const material = multibaseToMaterial(document.publicKeyMultibase!, "public")
      keypair.publicKey = await materialToKey(material, "public")
    }

    // missing key material
    if (!document.secretKeyMultibase && !document.publicKeyMultibase) {
      throw new SuiteError(
        ErrorCode.DECODING_ERROR,
        "Ed25519Keypair.import",
        "The key material is missing from the multibase object!",
      )
    }

    return keypair
  }
}
