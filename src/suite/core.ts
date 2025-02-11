import {
  type Credential,
  document,
  format,
  jcs,
  type Loader,
  ProcessingError,
  ProcessingErrorCode,
  type Proof,
  rdfc,
} from "@herculas/vc-data-integrity"

import { Ed25519Keypair } from "../key/keypair.ts"
import { sha256 } from "../utils/crypto.ts"

import * as SUITE_CONSTANT from "../constant/suite.ts"

/**
 * Transform an unsecured input document into a transformed document that is ready to be provided as input to the
 * hashing algorithm.
 *
 * @param {Credential} unsecuredDocument An unsecured input document to transform.
 * @param {object} options A set of options to use when transforming the document.
 *
 * @returns {Promise<string>} Resolve to a transformed data document.
 *
 * @see https://www.w3.org/TR/vc-di-eddsa/#transformation-eddsa-rdfc-2022
 */
export async function transformRDFC(
  unsecuredDocument: Credential,
  options: { proof: Proof; documentLoader: Loader },
): Promise<string> {
  // Procedure:
  //
  // 1. If `options.type` is not set to the string `DataIntegrityProof`, and `options.cryptosuite` is not set to the
  //    string `eddsa-rdfc-2022`, an error MUST be raised that SHOULD convey an error type of
  //    `PROOF_TRANSFORMATION_ERROR`.
  // 2. Let `canonicalDocument` be the result of converting `unsecuredDocument` to RDF statements, applying the RDF
  //    Dataset Canonicalization Algorithm to the result, and then serializing the result to a serialized canonical
  //    form.
  // 3. Return `canonicalDocument` as the transformed data document.

  if (options.proof.type !== SUITE_CONSTANT.GENERAL_PROOF_TYPE || options.proof.cryptosuite !== SUITE_CONSTANT.RDFC) {
    throw new ProcessingError(
      ProcessingErrorCode.PROOF_TRANSFORMATION_ERROR,
      "suite/core#transformRDFC",
      "The proof type or cryptosuite is not supported.",
    )
  }

  const canonicalDocument = await rdfc.normalize(unsecuredDocument, {
    algorithm: "URDNA2015",
    format: "application/n-quads",
    documentLoader: options.documentLoader,
  })

  return canonicalDocument
}

/**
 * Transform an unsecured input document into a transformed document that is ready to be provided as input to the
 * hashing algorithm.
 *
 * @param {Credential} unsecuredDocument An unsecured input document to transform.
 * @param {object} options A set of options to use when transforming the document.
 *
 * @returns {string} A transformed data document.
 *
 * @see https://www.w3.org/TR/vc-di-eddsa/#transformation-eddsa-jcs-2022
 */
export function transformJCS(unsecuredDocument: Credential, options: { proof: Proof }): string {
  // Procedure:
  //
  // 1. If `options.type` is not set to the string `DataIntegrityProof`, and `options.cryptosuite` is not set to the
  //    string `eddsa-jcs-2022`, an error MUST be raised that SHOULD convey an error type of
  //    `PROOF_TRANSFORMATION_ERROR`.
  // 2. Let `canonicalDocument` be the result of applying the JSON Canonicalization Scheme (JCS) to a JSON serialization
  //    of the `unsecuredDocument`.
  // 3. Return `canonicalDocument` as the transformed data document.

  if (options.proof.type !== SUITE_CONSTANT.GENERAL_PROOF_TYPE || options.proof.cryptosuite !== SUITE_CONSTANT.JCS) {
    throw new ProcessingError(
      ProcessingErrorCode.PROOF_TRANSFORMATION_ERROR,
      "suite/core#transformJCS",
      "The proof type or cryptosuite is not supported.",
    )
  }

  const canonicalDocument = jcs.canonize(unsecuredDocument)
  return canonicalDocument
}

/**
 * Generate a proof configuration from a set of proof options that is used as input to the proof hashing algorithm.
 *
 * @param {Credential} unsecuredDocument An unsecured input document to generate a proof configuration from.
 * @param {object} options A set of proof options to generate a proof configuration from.
 *
 * @returns {Promise<string>} Resolve to a proof configuration.
 *
 * @see https://www.w3.org/TR/vc-di-eddsa/#proof-configuration-eddsa-rdfc-2022
 */
export async function configRDFC(
  unsecuredDocument: Credential,
  options: { proof: Proof; documentLoader: Loader },
): Promise<string> {
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

  const proofConfig = structuredClone(options.proof)

  if (proofConfig.type !== SUITE_CONSTANT.GENERAL_PROOF_TYPE || proofConfig.cryptosuite !== SUITE_CONSTANT.RDFC) {
    throw new ProcessingError(
      ProcessingErrorCode.PROOF_GENERATION_ERROR,
      "suite/core#configRDFC",
      "The proof type or cryptosuite is not supported.",
    )
  }

  if (proofConfig.created && !Date.parse(proofConfig.created)) {
    throw new ProcessingError(
      ProcessingErrorCode.PROOF_GENERATION_ERROR,
      "suite/core#configRDFC",
      "The proof creation date is not a valid datetime.",
    )
  }

  proofConfig["@context"] = unsecuredDocument["@context"]

  const canonicalProofConfig = await rdfc.normalize(proofConfig, {
    algorithm: "URDNA2015",
    format: "application/n-quads",
    documentLoader: options.documentLoader,
  })

  return canonicalProofConfig
}

/**
 * Generate a proof configuration from a set of proof options that is used as input to the proof hashing algorithm.
 *
 * @param {object} options A set of proof options to generate a proof configuration from.
 *
 * @returns {string} A proof configuration.
 *
 * @see https://www.w3.org/TR/vc-di-eddsa/#proof-configuration-eddsa-jcs-2022
 */
export function configJCS(options: { proof: Proof }): string {
  // Procedure:
  //
  // 1. Let `proofConfig` be a clone of the `options` object.
  // 2. If `proofConfig.type` is not set to the string `DataIntegrityProof`, or `proofConfig.cryptosuite` is not set to
  //    the string `eddsa-jcs-2022`, an error MUST be raised that SHOULD convey an error type of
  //    `PROOF_GENERATION_ERROR`.
  // 3. If `proofConfig.created` is present and set to a value that is not valid datetime, an error MUST be raised
  //    and SHOULD convey an error type of `PROOF_GENERATION_ERROR`.
  // 4. Let `canonicalProofConfig` be the result of applying the JSON Canonicalization Scheme (JCS) to `proofConfig`.
  // 5. Return `canonicalProofConfig` as the proof configuration.

  const proofConfig = structuredClone(options.proof)

  if (proofConfig.type !== SUITE_CONSTANT.GENERAL_PROOF_TYPE || proofConfig.cryptosuite !== SUITE_CONSTANT.JCS) {
    throw new ProcessingError(
      ProcessingErrorCode.PROOF_GENERATION_ERROR,
      "suite/core#configJCS",
      "The proof type or cryptosuite is not supported.",
    )
  }

  if (proofConfig.created && !Date.parse(proofConfig.created)) {
    throw new ProcessingError(
      ProcessingErrorCode.PROOF_GENERATION_ERROR,
      "suite/core#configJCS",
      "The proof creation date is not a valid datetime.",
    )
  }

  const canonicalProofConfig = jcs.canonize(proofConfig)
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
 *
 * @see https://www.w3.org/TR/vc-di-eddsa/#hashing-eddsa-rdfc-2022
 * @see https://www.w3.org/TR/vc-di-eddsa/#hashing-eddsa-jcs-2022
 */
export async function hash(
  transformedDocument: string,
  canonicalProofConfig: string,
): Promise<Uint8Array> {
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
  const hashData = format.concatenate(proofConfigHash, transformedDocumentHash)
  return hashData
}

/**
 * Serialize a digital signature from a set of cryptographic hash data.
 *
 * @param {Uint8Array} hashData A cryptographic hash data to serialize.
 * @param {object} options A set of options to use when serializing the hash data.
 *
 * @returns {Promise<Uint8Array>} Resolve to a serialized digital proof.
 *
 * @see https://www.w3.org/TR/vc-di-eddsa/#proof-serialization-eddsa-rdfc-2022
 * @see https://www.w3.org/TR/vc-di-eddsa/#proof-serialization-eddsa-jcs-2022
 */
export async function serialize(
  hashData: Uint8Array,
  options: { proof: Proof; documentLoader: Loader },
): Promise<Uint8Array> {
  // Procedure:
  //
  // 1. Let `privateKeyBytes` be the result of retrieving the private key bytes associated with the
  //    `options.verificationMethod` value.
  // 2. Let `proofBytes` be the result of applying the Edwards-Curve Digital Signature Algorithm (EdDSA), using the
  //    `Ed25519` variant, with `hashData` as the data to be signed using the private key specified by
  //    `privateKeyBytes`. `proofBytes` will be exactly 64 bytes in size.
  // 3. Return `proofBytes` as the digital proof.

  const method = await document.retrieveVerificationMethod(options.proof.verificationMethod!, new Set(), {
    documentLoader: options.documentLoader,
  })
  const keypair = await Ed25519Keypair.import(method)
  if (!keypair.privateKey) {
    throw new ProcessingError(
      ProcessingErrorCode.INVALID_VERIFICATION_METHOD,
      "suite/core#serialize",
      "The specified verification method does not contain a private key.",
    )
  }
  const proofBytes = await crypto.subtle.sign(SUITE_CONSTANT.ALGORITHM, keypair.privateKey, hashData)
  return new Uint8Array(proofBytes)
}

/**
 * Verify a digital signature from a set of cryptographic hash data.
 *
 * @param {Uint8Array} hashData A cryptographic hash data to be verified.
 * @param {Uint8Array} proofBytes A digital proof to verify.
 * @param {object} options A set of options to use when verifying the digital proof.
 *
 * @returns {Promise<boolean>} Resolve to a verification result.
 *
 * @see https://www.w3.org/TR/vc-di-eddsa/#proof-verification-eddsa-rdfc-2022
 * @see https://www.w3.org/TR/vc-di-eddsa/#proof-verification-eddsa-jcs-2022
 */
export async function verify(
  hashData: Uint8Array,
  proofBytes: Uint8Array,
  options: { proof: Proof; documentLoader: Loader },
): Promise<boolean> {
  // Procedure:
  //
  // 1. Let `publicKeyBytes` be the result of retrieving the public key bytes associated with the
  //    `options.verificationMethod` value.
  // 2. Let `verificationResult` be the result of applying the verification algorithm for the Edwards-Curve Digital
  //    Signature Algorithm (EdDSA), using the `Ed25519` variant, with `hashData` as the data to be verified against
  //    the `proofBytes` using the public key specified by `publicKeyBytes`.
  // 3. Return `verificationResult` as the verification result.

  const method = await document.retrieveVerificationMethod(options.proof.verificationMethod!, new Set(), {
    documentLoader: options.documentLoader,
  })
  const keypair = await Ed25519Keypair.import(method)
  if (!keypair.publicKey) {
    throw new ProcessingError(
      ProcessingErrorCode.INVALID_VERIFICATION_METHOD,
      "suite/core#verify",
      "The specified verification method does not contain a public key.",
    )
  }
  const result = await crypto.subtle.verify(SUITE_CONSTANT.ALGORITHM, keypair.publicKey, proofBytes, hashData)
  return result
}
