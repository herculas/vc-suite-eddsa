import {
  canonize,
  concatenate,
  type CreateOptions,
  Cryptosuite,
  type PlainDocument,
  type Proof,
  sha256,
  type VerificationResult,
  type VerifyOptions,
} from "@herculas/vc-data-integrity"

import * as SUITE_CONSTANT from "../constants/suite.ts"

/**
 * The `eddsa-rdfc-2022` cryptographic suite takes an input document, canonicalizes the document using the RDF Dataset
 * Canonicalization algorithm, and then cryptographically hashes and signs the output resulting in the production of a
 * data integrity proof.
 *
 * @see https://www.w3.org/TR/vc-di-eddsa/#eddsa-rdfc-2022
 */
export class Ed25519RdfcSuite extends Cryptosuite {
  static override readonly cryptosuite: string = SUITE_CONSTANT.NAME_RDFC

  /**
   * Create a data integrity proof given an unsecured data document.
   *
   * @param {PlainDocument} unsecuredDocument An unsecured data document to create a proof for.
   * @param {CreateOptions} options A set of options to use when creating the proof.
   *
   * @returns {Promise<Proof>} Resolve to a data integrity proof.
   *
   * @see https://www.w3.org/TR/vc-di-eddsa/#create-proof-eddsa-rdfc-2022
   */
  static override async createProof(unsecuredDocument: PlainDocument, options: CreateOptions): Promise<Proof> {
    throw new Error("Method not implemented.")
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
  }

  /**
   * Verify a data integrity proof given a secured data document.
   *
   * @param {PlainDocument} securedDocument A secured data document to verify a proof for.
   * @param {VerifyOptions} options A set of options to use when verifying the proof.
   *
   * @returns {Promise<VerificationResult>} Resolve to a verification result.
   *
   * @see https://www.w3.org/TR/vc-di-eddsa/#verify-proof-eddsa-rdfc-2022
   */
  static override async verifyProof(
    securedDocument: PlainDocument,
    options: VerifyOptions,
  ): Promise<VerificationResult> {
    throw new Error("Method not implemented.")
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
  }

  /**
   * Transform an unsecured input document into a transformed document that is ready to be provided as input to the
   * hashing algorithm.
   *
   * @param {PlainDocument} unsecuredDocument An unsecured input document to transform.
   * @param {CreateOptions} options A set of options to use when transforming the document.
   *
   * @returns {Promise<string>} Resolve to a transformed data document.
   */
  private static async transform(unsecuredDocument: PlainDocument, options: CreateOptions): Promise<string> {
    // Procedure:
    //
    // 1. If `options.type` is not set to the string `DataIntegrityProof`, and `options.cryptosuite` is not set to the
    //    string `eddsa-rdfc-2022`, an error MUST be raised that SHOULD convey an error type of
    //    `PROOF_TRANSFORMATION_ERROR`.
    // 2. Let `canonicalDocument` be the result of converting `unsecuredDocument` to RDF statements, applying the RDF
    //    Dataset Canonicalization Algorithm to the result, and then serializing the result to a serialized canonical
    //    form.
    // 3. Return `canonicalDocument` as the transformed data document.

    if (options.proof.type !== Ed25519RdfcSuite.type || options.proof.cryptosuite !== Ed25519RdfcSuite.cryptosuite) {
      // TODO: basic error handling
      throw new Error("PROOF_TRANSFORMATION_ERROR")
    }

    const canonicalDocument = await canonize(unsecuredDocument, {
      algorithm: "URDNA2015",
      format: "application/n-quads",
      documentLoader: options.loader!,
    })

    return canonicalDocument
  }

  /**
   * Generate a proof configuration from a set of proof options that is used as input to the proof hashing algorithm.
   *
   * @param {PlainDocument} unsecuredDocument An unsecured input document to generate a proof configuration from.
   * @param {CreateOptions} options A set of proof options to generate a proof configuration from.
   *
   * @returns {Promise<string>} Resolve to a proof configuration.
   */
  private static async config(unsecuredDocument: PlainDocument, options: CreateOptions): Promise<string> {
    // Procedure:
    //
    // 1. Let `proofConfig` be a clone of the `options` object.
    // 2. If `proofConfig.type` is not set to the string `DataIntegrityProof`, and/or `proofConfig.cryptosuite` is not
    //    set to the string `eddsa-rdfc-2022`, an error MUST be raised that SHOULD convey an error type of
    //    `PROOF_GENERATION_ERROR`.
    // 3. If `proofConfig.created` is present and set to a value that is not valid datetime, an error MUST be raised
    //    and SHOULD convey an error type of `PROOF_GENERATION_ERROR`.
    // 4. Set `proofConfig.@context` to `unsecuredDocument.@context`.
    // 5. Let `canonicalProofConfig` be the result of applying the RDF Dataset Canonicalization Algorithm to the
    //    `proofConfig`.
    // 6. Return `canonicalProofConfig` as the proof configuration.

    const proofConfig = { ...options.proof }

    if (proofConfig.type !== Ed25519RdfcSuite.type || proofConfig.cryptosuite !== Ed25519RdfcSuite.cryptosuite) {
      throw new Error("PROOF_GENERATION_ERROR")
    }

    if (proofConfig.created && !Date.parse(proofConfig.created)) {
      throw new Error("PROOF_GENERATION_ERROR")
    }

    proofConfig["@context"] = unsecuredDocument["@context"]

    const canonicalProofConfig = await canonize(proofConfig, {
      algorithm: "URDNA2015",
      format: "application/n-quads",
      documentLoader: options.loader!,
    })

    return canonicalProofConfig
  }

  /**
   * Cryptographically hash a transformed data document and proof configuration into cryptographic hash data that is
   * ready to be provided as input to the proof serialization algorithm and proof verification algorithm.
   *
   * @param {string} transformedDocument A transformed data document to be hashed.
   * @param {string} canonicalProofConfig A canonical proof configuration.
   *
   * @returns {Promise<Uint8Array>} Resolve to a single hash data represented as series of bytes.
   */
  private static async hash(transformedDocument: string, canonicalProofConfig: string): Promise<Uint8Array> {
    // Procedure:
    //
    // 1. Let `proofConfigHash` be the result of applying the SHA-256 cryptographic hash algorithm to the
    //    `canonicalProofConfig`. The `proofConfigHash` will be exactly 32 bytes in size.
    // 2. Let `transformedDocumentHash` be the result of applying the SHA-256 cryptographic hash algorithm to the
    //    `transformedDocument`. The `transformedDocumentHash` will be exactly 32 bytes in size.
    // 3. Let `hashData` be the result of concatenating `proofConfigHash` followed by `transformedDocumentHash`.
    // 4. Return `hashData` as the hash data.

    const proofConfigHash = await sha256(canonicalProofConfig)
    const transformedDocumentHash = await sha256(transformedDocument)
    const hashData = concatenate(proofConfigHash, transformedDocumentHash)
    return hashData
  }

  /**
   * Serialize a digital signature from a set of cryptographic hash data.
   *
   * @param {Uint8Array} hashData A cryptographic hash data to serialize.
   * @param {CreateOptions} options A set of options to use when serializing the hash data.
   *
   * @returns {Promise<string>} Resolve to a serialized digital proof.
   */
  private static async serialize(hashData: Uint8Array, options: CreateOptions): Promise<string> {
    throw new Error("Method not implemented.")
    // Procedure:
    //
    // 1. Let `privateKeyBytes` be the result of retrieving the private key bytes associated with the
    //    `options.verificationMethod` value.
    // 2. Let `proofBytes` be the result of applying the Edwards-Curve Digital Signature Algorithm (EdDSA), using the
    //    `Ed25519` variant, with `hashData` as the data to be signed using the private key specified by
    //    `privateKeyBytes`. `proofBytes` will be exactly 64 bytes in size.
    // 3. Return `proofBytes` as the digital proof.

    // TODO: retrieve the private key bytes associated with the options.verificationMethod value
  }

  private static async verify() {}
}
