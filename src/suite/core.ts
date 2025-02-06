import { base58 } from "@scure/base"
import type { VerificationResult } from "@herculas/vc-data-integrity"

import { SuiteError } from "../error/error.ts"
import { ErrorCode } from "../error/constants.ts"
import * as PREFIX_CONSTANT from "../constants/prefix.ts"
import * as SUITE_CONSTANT from "../constants/suite.ts"

/**
 * Sign a message in `Uint8Array` format with a `Ed25519Keypair`.
 *
 * @param {Uint8Array} data The message to be signed.
 * @param {CryptoKey} privateKey The private key to sign the message.
 *
 * @returns {Promise<Uint8Array>} The signature of the message.
 */
export async function sign(
  data: Uint8Array,
  privateKey: CryptoKey,
): Promise<Uint8Array> {
  const signature = await crypto.subtle.sign(SUITE_CONSTANT.ALGORITHM, privateKey, data)
  return new Uint8Array(signature)
}

/**
 * Verify a signature against a message with a public key.
 *
 * @param {Uint8Array} data The message to be verified.
 * @param {Uint8Array} signature The signature to be verified.
 * @param {CryptoKey} [publicKey] The public key to verify the signature.
 *
 * @returns {Promise<VerificationResult>} The result of the verification.
 */
export async function verify(
  data: Uint8Array,
  signature: string,
  publicKey?: CryptoKey,
): Promise<VerificationResult> {
  try {
    if (!publicKey) {
      throw new SuiteError(
        ErrorCode.KEY_NOT_FOUND,
        "suite/core.verify",
        "The keypair does not have a public key.",
      )
    }

    if (!signature.startsWith(PREFIX_CONSTANT.BASE_58_BTC)) {
      throw new SuiteError(
        ErrorCode.FORMAT_ERROR,
        "suite/core.verify",
        "The signature is not in the correct format.",
      )
    }
    const signatureBytes = base58.decode(signature.slice(PREFIX_CONSTANT.BASE_58_BTC.length))
    return {
      verified: await crypto.subtle.verify(SUITE_CONSTANT.ALGORITHM, publicKey, signatureBytes, data),
    }
  } catch (error) {
    return {
      verified: false,
      errors: error as SuiteError,
    }
  }
}

//   override async sign(
//     _document: PlainDocument,
//     _proof: Proof,
//     _verifyData: Uint8Array,
//     _loader?: Loader,
//   ): Promise<Proof> {
//     const keypair = this.keypair as Ed25519Keypair
//     const signature = await sign(_verifyData, keypair.privateKey)
//     _proof.proofValue = signature
//     return _proof
//   }

//   override async verify(
//     _document: PlainDocument,
//     _proof: Proof,
//     _verifyData: Uint8Array,
//     _method?: VerificationMethodMap,
//     _loader?: Loader,
//   ): Promise<VerificationResult> {
//     try {
//       // check if the proof value is present
//       if (!_proof.proofValue) {
//         throw new SuiteError(
//           SuiteErrorCode.FORMAT_ERROR,
//           "suite/signature.verify",
//           "The proof value is missing.",
//         )
//       }

//       // get the proper public key
//       let publicKey: CryptoKey
//       if (_method) {
//         // if verification method is provided, use it
//         const loadedKeypair = await Ed25519Keypair.import(_method, { type: _method.publicKeyJwk ? "jwk" : "multibase" })
//         publicKey = loadedKeypair.publicKey!
//       } else {
//         // otherwise, use the keypair
//         const keypair = this.keypair as Ed25519Keypair
//         if (!keypair.publicKey) {
//           throw new SuiteError(
//             SuiteErrorCode.KEY_NOT_FOUND,
//             "suite/signature.verify",
//             "The public key is missing.",
//           )
//         }
//         publicKey = keypair.publicKey
//       }

//       // verify the signature
//       const result = await verify(_verifyData, _proof.proofValue, publicKey)
//       return {
//         verified: result.verified,
//         errors: result.errors,
//       }
//     } catch (error) {
//       return {
//         verified: false,
//         errors: error as SuiteError,
//       }
//     }
//   }
// }
