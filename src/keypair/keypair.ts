import { concatenate, type DIDURL, Keypair, type URL, type VerificationResult } from "@crumble-jon/ld-crypto-syntax"

import * as KEYPAIR_CONSTANT from "./constants.ts"
import { generateKeypair, keyToMaterial, materialToMultibase } from "./core.ts"
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
   * @param {URL} [_id] The identifier of the keypair.
   * @param {DIDURL} [_controller] The controller of the keypair.
   * @param {Date} [_revoked] The date and time when the keypair has been revoked.
   * @param {string} [_publicKeyMultibase] The multibase encoded public key.
   * @param {string} [_privateKeyMultibase] The multibase encoded private key.
   */
  constructor(
    _id?: URL,
    _controller?: DIDURL,
    _revoked?: Date,
  ) {
    super(KEYPAIR_CONSTANT.SUITE_TYPE, _id, _controller, _revoked)
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
   * @returns {KeypairDocument} The serialized keypair to be exported.
   */
  // override export(options: KeypairExportOptions): KeypairDocument {
  //   if (!options.flag) {
  //     options.flag = "public"
  //   }

  //   // if ((pkFlag && !this.publicKeyMultibase) || (skFlag && !this.privateKeyMultibase)) {
  //   //   throw new Error("Keypair has not been generated!")
  //   // }

  //   // if (!this.id || !this.controller) {
  //   //   throw new Error("Keypair is missing required fields!")
  //   // }

  //   // return {
  //   //   "@context": CONTEXT_URL.SUITE_2020,
  //   //   id: this.id,
  //   //   controller: this.controller,
  //   //   revoked: this.revoked ? toW3CTimestampString(this.revoked) : undefined,
  //   //   type: this.type,
  //   //   publicKeyMultibase: pkFlag ? this.publicKeyMultibase : undefined,
  //   //   privateKeyMultibase: skFlag ? this.privateKeyMultibase : undefined,
  //   // }
  // }

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
