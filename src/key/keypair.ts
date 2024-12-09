import { Keypair, toW3CTimestampString } from "@crumble-jon/ld-crypto-syntax"
import { base58 } from "@scure/base"

import { encodeMultibaseKey, isValidKeyPrefix } from "../util.ts"
import { generateRawKeypair } from "./core.ts"

const SUITE_ID = "ED25519_KEYPAIR"
const SUITE_CONTEXT = "https://w3id.org/security/suites/ed25519-2020/v1"

const MULTICODEC_PUB_PREFIX = new Uint8Array([0xed, 0x01])
const MULTICODEC_PRI_PREFIX = new Uint8Array([0x80, 0x26])

export class ED25519Keypair extends Keypair {
  publicKeyMultibase?: string
  privateKeyMultibase?: string

  constructor(
    controller?: string,
    id?: string,
    revoked?: Date,
    publicKeyMultibase?: string,
    privateKeyMultibase?: string,
  ) {
    super(SUITE_ID, id, controller, revoked)

    if (!isValidKeyPrefix(MULTICODEC_PUB_PREFIX, publicKeyMultibase)) {
      throw new Error("Invalid public key prefix!")
    }
    if (!isValidKeyPrefix(MULTICODEC_PRI_PREFIX, privateKeyMultibase)) {
      throw new Error("Invalid private key prefix!")
    }

    this.publicKeyMultibase = publicKeyMultibase
    this.privateKeyMultibase = privateKeyMultibase

    // set identifier if controller is provided
    if (this.controller && !this.id) {
      this.id = `${this.controller}#${this.fingerprint()}`
    }

    if (this._publicKeyBuffer && this._publicKeyBuffer.length !== 32) {
      throw new Error("Invalid public key length!")
    }
  }

  /**
   * Generate a new keypair.
   *
   * @param {Uint8Array} seed A seed to generate the keypair from. If not provided, a random seed will be used.
   */
  override generate(seed?: Uint8Array) {
    const keypair = generateRawKeypair(seed)
    const publicKeyMultibase = encodeMultibaseKey(MULTICODEC_PUB_PREFIX, keypair.publicKey)
    const privateKeyMultibase = encodeMultibaseKey(MULTICODEC_PRI_PREFIX, keypair.privateKey)
    
    if (!isValidKeyPrefix(MULTICODEC_PUB_PREFIX, publicKeyMultibase)) {
      throw new Error("Invalid public key prefix!")
    }
    if (!isValidKeyPrefix(MULTICODEC_PRI_PREFIX, privateKeyMultibase)) {
      throw new Error("Invalid private key prefix!")
    }

    this.publicKeyMultibase = publicKeyMultibase
    this.privateKeyMultibase = privateKeyMultibase
  }

  /**
   * Calculate the public key fingerprint, multibase + multicodec encoded. The specific fingerprint method is
   * determined by the key suite, and is often either a hash of the public key material, or the full encoded public
   * key.
   *
   * This method is frequently used to initialize the key identifier or generate some types of cryptonym DIDs.
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
   * Export the serialized representation of the keypair, along with other metadata which can be used to form a proof.
   *
   * @param {boolean} pkFlag Whether to include the public key in the export.
   * @param {boolean} skFlag Whether to include the private key in the export.
   *
   * @returns {object} The serialized keypair to be exported.
   */
  override export(pkFlag: boolean, skFlag: boolean): object {
    if (!pkFlag && !skFlag) {
      throw new Error("Either public key or private key must be exported!")
    }
    
    if ((pkFlag && !this.publicKeyMultibase) || (skFlag && !this.privateKeyMultibase)) {
      throw new Error("Keypair has not been generated!")
    }

    type Exported = {
      [any: string]: string
    }

    const exported: Exported = {}
    exported['@context'] = SUITE_CONTEXT
    exported['type'] = this.type

    if (this.id) {
      exported['id'] = this.id
    }

    if (this.controller) {
      exported['controller'] = this.controller
    }

    if (this.revoked) {
      exported['revoked'] = toW3CTimestampString(this.revoked)
    }

    if (pkFlag && this.publicKeyMultibase) {
      exported['publicKeyMultibase'] = this.publicKeyMultibase
    }

    if (skFlag && this.privateKeyMultibase) {
      exported['privateKeyMultibase'] = this.privateKeyMultibase
    }

    return exported
  }
  

  /**
   * @returns {Uint8Array} Public key bytes.
   */
  get _publicKeyBuffer(): Uint8Array | undefined {
    if (!this.publicKeyMultibase) return undefined
    const pkMulticodec = base58.decode(this.publicKeyMultibase.substring(1))
    const pkBytes = pkMulticodec.slice(MULTICODEC_PUB_PREFIX.length)
    return pkBytes
  }
}

interface GenerateOptions {
  seed?: Uint8Array
  controller?: string
  id?: string
  revoked?: Date
}
