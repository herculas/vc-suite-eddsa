import {
  type Loader,
  type PlainDocument,
  type Proof,
  Signature,
  type VerificationMethodMap,
  type VerificationResult,
} from "@crumble-jon/ld-crypto-syntax"

import * as CONTEXT_URL from "../context/constants.ts"
import * as SUITE_CONSTANT from "./constants.ts"
import { Ed25519Keypair } from "../keypair/keypair.ts"
import { sign, verify } from "./core.ts"
import { SuiteError } from "../error/error.ts"
import { SuiteErrorCode } from "../error/constants.ts"

export class Ed25519Signature extends Signature {
  constructor(_keypair: Ed25519Keypair, _time?: Date, _proof?: Proof) {
    super(SUITE_CONSTANT.TYPE, _keypair, CONTEXT_URL.SUITE_2020, _time, _proof)
  }

  override async sign(
    _document: PlainDocument,
    _proof: Proof,
    _verifyData: Uint8Array,
    _loader?: Loader,
  ): Promise<Proof> {
    const keypair = this.keypair as Ed25519Keypair
    const signature = await sign(_verifyData, keypair.privateKey)
    _proof.proofValue = signature
    return _proof
  }

  override async verify(
    _document: PlainDocument,
    _proof: Proof,
    _verifyData: Uint8Array,
    _method?: VerificationMethodMap,
    _loader?: Loader,
  ): Promise<VerificationResult> {
    try {
      // check if the proof value is present
      if (!_proof.proofValue) {
        throw new SuiteError(
          SuiteErrorCode.FORMAT_ERROR,
          "suite/signature.verify",
          "The proof value is missing.",
        )
      }

      // get the proper public key
      let publicKey: CryptoKey
      if (_method) {
        // if verification method is provided, use it
        const loadedKeypair = await Ed25519Keypair.import(_method, { type: _method.publicKeyJwk ? "jwk" : "multibase" })
        publicKey = loadedKeypair.publicKey!
      } else {
        // otherwise, use the keypair
        const keypair = this.keypair as Ed25519Keypair
        if (!keypair.publicKey) {
          throw new SuiteError(
            SuiteErrorCode.KEY_NOT_FOUND,
            "suite/signature.verify",
            "The public key is missing.",
          )
        }
        publicKey = keypair.publicKey
      }

      // verify the signature
      const result = await verify(_verifyData, _proof.proofValue, publicKey)
      return {
        verified: result.verified,
        errors: result.errors,
      }
    } catch (error) {
      return {
        verified: false,
        errors: error as SuiteError,
      }
    }
  }
}
