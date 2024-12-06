import { Keypair } from "@crumble-jon/ld-crypto-syntax"
import { base58 } from "@scure/base"

import { isValidKeyPrefix } from "../util.ts"

const SUITE_ID = "ED25519_KEYPAIR"
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

  override generate(options: object): Promise<Keypair> {
    throw new Error("Method not implemented.")
  }

  override fromDocument(document: object, checkContext: boolean, checkRevoked: boolean): Promise<Keypair> {
    throw new Error("Method not implemented.")
  }

  override from(options: object): Promise<Keypair> {
    throw new Error("Method not implemented.")
  }

  override export(pkFlag: boolean, skFlag: boolean): object {
    throw new Error("Method not implemented.")
  }

  override fingerprint(): string {
    throw new Error("Method not implemented.")
  }

  override verifyFingerprint(fingerprint: string): boolean {
    throw new Error("Method not implemented.")
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
