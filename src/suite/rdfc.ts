import {
  type Credential,
  Cryptosuite,
  type JsonLdDocument,
  type LoadDocumentCallback,
  multi,
  type Proof,
  type Verification,
} from "@herculas/vc-data-integrity"

import * as core from "./core.ts"
import * as SUITE_CONSTANT from "../constant/suite.ts"

/**
 * The `eddsa-rdfc-2022` cryptographic suite takes an input document, canonicalizes the document using the RDF Dataset
 * Canonicalization algorithm, and then cryptographically hashes and signs the output resulting in the production of a
 * data integrity proof.
 *
 * @see https://www.w3.org/TR/vc-di-eddsa/#eddsa-rdfc-2022
 */
export class EddsaRdfc2022 extends Cryptosuite {
  /**
   * The name of the cryptographic suite.
   *
   * In this suite, this value MUST be `eddsa-rdfc-2022`.
   */
  static override readonly cryptosuite: string = SUITE_CONSTANT.SUITE_RDFC

  /**
   * Create a data integrity proof given an unsecured data document.
   *
   * @param {JsonLdDocument} unsecuredDocument An unsecured data document to create a proof for.
   * @param {object} options A set of options to use when creating the proof.
   *
   * @returns {Promise<Proof>} Resolve to a data integrity proof.
   *
   * @see https://www.w3.org/TR/vc-di-eddsa/#create-proof-eddsa-rdfc-2022
   */
  static override async createProof(
    unsecuredDocument: JsonLdDocument,
    options: {
      proof: Proof
      documentLoader: LoadDocumentCallback
    },
  ): Promise<Proof> {
    // Procedure:
    //
    // 1. Let `proof` be a clone of `options`.
    // 2. Let `proofConfig` be the result of running the proof configuration algorithm with `options` passed as a
    //    parameter.
    // 3. Let `transformedData` be the result of running the transformation algorithm with `unsecuredDocument`,
    //    `proofConfig`, and `options` passed as parameters.
    // 4. Let `hashData` be the result of running the hashing algorithm with `transformedData` and `proofConfig` passed
    //    as parameters.
    // 5. Let `proofBytes` be the result of running the proof serialization algorithm with `hashData` and `options`
    //    passed as parameters.
    // 6. Let `proof.proofValue` be a base58-btc-encoded multibase value of `proofBytes`.
    // 7. Return `proof` as the data integrity proof.

    const proof = structuredClone(options.proof)

    const canonicalProofConfig = await core.configRdfc(unsecuredDocument as Credential, options)
    const canonicalDocument = await core.transformRdfc(unsecuredDocument as Credential, options)
    const hashData = await core.hash(canonicalDocument, canonicalProofConfig)
    const proofBytes = await core.serialize(hashData, options)

    proof.proofValue = multi.base58btc.encode(proofBytes)
    return proof
  }

  /**
   * Verify a data integrity proof given a secured data document.
   *
   * @param {JsonLdDocument} securedDocument A secured data document to verify a proof for.
   * @param {object} options A set of options to use when verifying the proof.
   *
   * @returns {Promise<Result.Verification>} Resolve to a verification result.
   *
   * @see https://www.w3.org/TR/vc-di-eddsa/#verify-proof-eddsa-rdfc-2022
   */
  static override async verifyProof(
    securedDocument: JsonLdDocument,
    options: {
      documentLoader: LoadDocumentCallback
    },
  ): Promise<Verification> {
    // Procedure:
    //
    // 1. Let `unsecuredDocument` be a copy of `securedDocument` with the `proof` property removed.
    // 2. Let `proofOptions` be the result of a copy of `securedDocument.proof` with the `proofValue` property removed.
    // 3. Let `proofBytes` be the multibase decoded base58-btc value in `securedDocument.proof.proofValue`.
    // 4. Let `transformedData` be the result of running the transformation algorithm with `unsecuredDocument` and
    //    `proofOptions` passed as parameters.
    // 5. Let `proofConfig` be the result of running the proof configuration algorithm with `unsecuredDocument` and
    //    `proofOptions` passed as parameters.
    // 6. Let `hashData` be the result of running the hashing algorithm with `transformedData` and `proofConfig` passed
    //    as parameters.
    // 7. Let `verified` be the result of running the proof verification algorithm with `hashData`, `proofBytes`, and
    //    `proofConfig` passed as parameters.
    // 8. Return a verification result with `verified` and `verifiedDocument` set to `unsecuredDocument` if `verified`
    //    is `true`.

    const securedCredential = securedDocument as Credential

    const unsecuredCredential = structuredClone(securedCredential)
    delete unsecuredCredential.proof

    const proofOptions = structuredClone(securedCredential.proof) as Proof
    delete proofOptions.proofValue

    const proofBytes = multi.base58btc.decode((securedCredential.proof as Proof).proofValue!)
    const transformOptions = { proof: proofOptions, documentLoader: options.documentLoader }

    const canonicalDocument = await core.transformRdfc(unsecuredCredential, transformOptions)
    const canonicalProofConfig = await core.configRdfc(unsecuredCredential, transformOptions)
    const hashData = await core.hash(canonicalDocument, canonicalProofConfig)
    const verified = await core.verify(hashData, proofBytes, transformOptions)

    return {
      verified,
      verifiedDocument: verified ? unsecuredCredential : undefined,
    }
  }
}
