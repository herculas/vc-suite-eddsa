import { type DIDURL, Keypair, toW3CTimestampString, type URL } from "@crumble-jon/ld-crypto-syntax"
import * as CONTEXT_URL from "../context/constants.ts"
import * as KEYPAIR_CONSTANTS from "./constants.ts"
import { assertKeyPrefix, decodeMultibase, encodeMultibase, generateRawKeypair } from "./core.ts"
import type { KeypairDocument } from "../types/keypair/document.ts"

export class Ed25519Keypair extends Keypair {
  publicKeyMultibase?: string
  privateKeyMultibase?: string

  constructor(id?: URL, controller?: DIDURL, revoked?: Date, pkMultibase?: string, skMultibase?: string) {
    super(KEYPAIR_CONSTANTS.SUITE_TYPE, id, controller, revoked)
    if (pkMultibase) {
      assertKeyPrefix(pkMultibase, KEYPAIR_CONSTANTS.MULTI_CODEC_PUBLIC_PREFIX)
      this.publicKeyMultibase = pkMultibase
    }
    if (skMultibase) {
      assertKeyPrefix(skMultibase, KEYPAIR_CONSTANTS.MULTI_CODEC_PRIVATE_PREFIX)
      this.privateKeyMultibase = skMultibase
    }

    // set identifier if controller is provided
    if (this.controller && !this.id) {
      this.id = `${this.controller}#${this.fingerprint()}`
    }

    if (this._pkBuffer && this._pkBuffer.length !== 32) {
      throw new Error("Invalid public key length!")
    }
  }

  /**
   * Generate a new Ed25519 keypair.
   */
  override async generate() {
    const keypair = await generateRawKeypair()
    const pkMultibase = encodeMultibase(keypair.publicKey, KEYPAIR_CONSTANTS.MULTI_CODEC_PUBLIC_PREFIX)
    const skMultibase = encodeMultibase(keypair.privateKey, KEYPAIR_CONSTANTS.MULTI_CODEC_PRIVATE_PREFIX)

    assertKeyPrefix(pkMultibase, KEYPAIR_CONSTANTS.MULTI_CODEC_PUBLIC_PREFIX)
    assertKeyPrefix(skMultibase, KEYPAIR_CONSTANTS.MULTI_CODEC_PRIVATE_PREFIX)

    this.publicKeyMultibase = pkMultibase
    this.privateKeyMultibase = skMultibase
  }

  /**
   * Calculate the public key fingerprint, multibase + multicodec encoded. The specific fingerprint method is determined
   * by the key suite, and is often either a hash of the public key material, or the full encoded public key. This
   * method is frequently used to initialize the key identifier or generate some types of cryptonym DIDs.
   *
   * @returns {string} The fingerprint.
   */
  override fingerprint(): string {
    if (!this.publicKeyMultibase) {
      throw new Error("Have not generated keypair yet!")
    }
    return this.publicKeyMultibase
  }

  /**
   * Verify that a provided fingerprint matches the public key material belonging to this keypair.
   *
   * @param {string} fingerprint A public key fingerprint.
   *
   * @returns {boolean} `true` if the fingerprint matches the public key material, `false` otherwise.
   */
  override verifyFingerprint(fingerprint: string): boolean {
    return this.fingerprint() === fingerprint
  }

  /**
   * Export the serialized representation of the keypair, along with other metadata which can be used to form a proof.
   *
   * @param {string} flag Whether to include the public key in the export.
   *
   * @returns {KeypairDocument} The serialized keypair to be exported.
   */
  override export(flag: "private" | "public" | "both"): KeypairDocument {
    const pkFlag = flag === "public" || flag === "both"
    const skFlag = flag === "private" || flag === "both"

    if ((pkFlag && !this.publicKeyMultibase) || (skFlag && !this.privateKeyMultibase)) {
      throw new Error("Keypair has not been generated!")
    }

    if (!this.id || !this.controller) {
      throw new Error("Keypair is missing required fields!")
    }

    return {
      "@context": CONTEXT_URL.SUITE_2020,
      id: this.id,
      controller: this.controller,
      revoked: this.revoked ? toW3CTimestampString(this.revoked) : undefined,
      type: this.type,
      publicKeyMultibase: pkFlag ? this.publicKeyMultibase : undefined,
      privateKeyMultibase: skFlag ? this.privateKeyMultibase : undefined,
    }
  }

  get _pkBuffer(): Uint8Array | undefined {
    if (!this.publicKeyMultibase) return undefined
    const pkMultiCodec = decodeMultibase(this.publicKeyMultibase)
    const pkBytes = pkMultiCodec.slice(KEYPAIR_CONSTANTS.MULTI_CODEC_PUBLIC_PREFIX.length)
    return pkBytes
  }
}
