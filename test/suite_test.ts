import { assert, assertEquals } from "@std/assert"
import type { Credential, Proof } from "@herculas/vc-data-integrity"

import { base58btc } from "../src/utils/encode.ts"
import { configRDFC, hash, serialize, transformRDFC, verify } from "../src/suite/core.ts"
import { EddsaRdfc2022 } from "../src/mod.ts"
import { testLoader } from "./mock/loader.ts"
import { EddsaJcs2022 } from "../src/suite/jcs.ts"

import * as UNSECURED_CRED_1 from "./mock/unsecured-credential-1.json" with { type: "json" }
import * as UNSECURED_CRED_2 from "./mock/unsecured-credential-2.json" with { type: "json" }
import * as PROOF_OPTIONS_1 from "./mock/proof-options-1.json" with { type: "json" }
import * as PROOF_OPTIONS_2 from "./mock/proof-options-2.json" with { type: "json" }

const bytesToHex = (arr: Uint8Array) => arr.reduce((acc, i) => acc + i.toString(16).padStart(2, "0"), "")
const hexToBytes = (hex: string) => new Uint8Array(hex.match(/.{1,2}/g)!.map((byte) => parseInt(byte, 16)))

Deno.test("EdDSA-RDFC-2022 document and proof hashing", async () => {
  const unsecuredCredential = structuredClone(UNSECURED_CRED_1.default) as Credential
  const proofOptions = structuredClone(PROOF_OPTIONS_1.default) as Proof

  const transformOptions = { proof: proofOptions, documentLoader: testLoader }
  const canonicalDocument = await transformRDFC(unsecuredCredential, transformOptions)
  const canonicalProofConfig = await configRDFC(unsecuredCredential, transformOptions)

  const hashData = await hash(canonicalDocument, canonicalProofConfig)

  const expectedDocumentHash = "517744132ae165a5349155bef0bb0cf2258fff99dfe1dbd914b938d775a36017"
  const expectedProofHash = "bea7b7acfbad0126b135104024a5f1733e705108f42d59668b05c0c50004c6b0"

  assertEquals(bytesToHex(hashData), expectedProofHash + expectedDocumentHash)
})

Deno.test("EdDSA-RDFC-2022 proof creation", async () => {
  const proofOptions = structuredClone(PROOF_OPTIONS_1.default) as Proof

  const documentHash = "517744132ae165a5349155bef0bb0cf2258fff99dfe1dbd914b938d775a36017"
  const proofHash = "bea7b7acfbad0126b135104024a5f1733e705108f42d59668b05c0c50004c6b0"
  const hashData = proofHash + documentHash

  const transformOptions = { proof: proofOptions, documentLoader: testLoader }
  const proofBytes = await serialize(hexToBytes(hashData), transformOptions)

  assertEquals(
    base58btc.encode(proofBytes),
    "z2YwC8z3ap7yx1nZYCg4L3j3ApHsF8kgPdSb5xoS1VR7vPG3F561B52hYnQF9iseabecm3ijx4K1FBTQsCZahKZme",
  )
})

Deno.test("EdDSA-RDFC-2022 proof verification", async () => {
  const proofOptions = structuredClone(PROOF_OPTIONS_1.default) as Proof

  const documentHash = "517744132ae165a5349155bef0bb0cf2258fff99dfe1dbd914b938d775a36017"
  const proofHash = "bea7b7acfbad0126b135104024a5f1733e705108f42d59668b05c0c50004c6b0"
  const proofEncoded = "z2YwC8z3ap7yx1nZYCg4L3j3ApHsF8kgPdSb5xoS1VR7vPG3F561B52hYnQF9iseabecm3ijx4K1FBTQsCZahKZme"

  const hashData = hexToBytes(proofHash + documentHash)
  const proofBytes = base58btc.decode(proofEncoded)

  const verifyOptions = { proof: proofOptions, documentLoader: testLoader }
  const result = await verify(hashData, proofBytes, verifyOptions)

  assert(result)
})

Deno.test("EdDSA-RDFC-2022 proof creation and verification: encapsulated", async () => {
  const unsecuredCredential = structuredClone(UNSECURED_CRED_1.default) as Credential
  const proofOptions = structuredClone(PROOF_OPTIONS_1.default) as Proof

  const proveOptions = { proof: proofOptions, documentLoader: testLoader }
  const proof = await EddsaRdfc2022.createProof(unsecuredCredential, proveOptions)

  const securedCredential = unsecuredCredential
  securedCredential.proof = proof

  const verifyOptions = { documentLoader: testLoader }
  const result = await EddsaRdfc2022.verifyProof(securedCredential, verifyOptions)

  assert(result.verified)
  assertEquals(
    securedCredential.proof.proofValue,
    "z2YwC8z3ap7yx1nZYCg4L3j3ApHsF8kgPdSb5xoS1VR7vPG3F561B52hYnQF9iseabecm3ijx4K1FBTQsCZahKZme",
  )
})

Deno.test("EdDSA-RDFC-2022 proof creation and verification: encapsulated 2", async () => {
  const unsecuredCredential = structuredClone(UNSECURED_CRED_2.default) as Credential
  const proofOptions = structuredClone(PROOF_OPTIONS_1.default) as Proof

  const proveOptions = { proof: proofOptions, documentLoader: testLoader }
  const proof = await EddsaRdfc2022.createProof(unsecuredCredential, proveOptions)

  const securedCredential = unsecuredCredential
  securedCredential.proof = proof

  const verifyOptions = { documentLoader: testLoader }
  const result = await EddsaRdfc2022.verifyProof(securedCredential, verifyOptions)

  assert(result.verified)
  assertEquals(
    securedCredential.proof.proofValue,
    "zeuuS9pi2ZR8Q41bFFJKS9weSWkwa7pRcxHTHzxjDEHtVSZp3D9Rm3JdzT82EQpmXMb9wvfFJLuDPeSXZaRX1q1c",
  )
})

Deno.test("EdDSA-JCS-2022 proof creation and verification: encapsulated", async () => {
  const unsecuredCredential = structuredClone(UNSECURED_CRED_1.default) as Credential
  const proofOptions = structuredClone(PROOF_OPTIONS_2.default) as Proof

  const proveOptions = { proof: proofOptions, documentLoader: testLoader }
  const proof = await EddsaJcs2022.createProof(unsecuredCredential, proveOptions)

  const securedCredential = unsecuredCredential
  securedCredential.proof = proof

  const verifyOptions = { documentLoader: testLoader }
  const result = await EddsaJcs2022.verifyProof(securedCredential, verifyOptions)

  assert(result.verified)
  assertEquals(
    securedCredential.proof.proofValue,
    "z2HnFSSPPBzR36zdDgK8PbEHeXbR56YF24jwMpt3R1eHXQzJDMWS93FCzpvJpwTWd3GAVFuUfjoJdcnTMuVor51aX",
  )
})
