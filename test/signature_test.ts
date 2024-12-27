import { assert } from "@std/assert/assert"
import { canonize, type PlainDocument, Purpose } from "@crumble-jon/ld-crypto-syntax"

import { Ed25519Keypair } from "../src/keypair/keypair.ts"
import { Ed25519Signature } from "../src/suite/signature.ts"
import { sign, verify } from "../src/suite/core.ts"
import { customLoader, loader } from "./loader.ts"

Deno.test("basic signing and verifying", async () => {
  const keypair = new Ed25519Keypair()
  await keypair.initialize()

  const message = new Uint8Array(1024)
  crypto.getRandomValues(message)

  const signature = await sign(message, keypair)
  const result = await verify(message, signature, keypair)

  console.log("signature:", signature)
  assert(result.verified)
})

Deno.test("ensemble signing and verifying", async () => {
  const keypair = new Ed25519Keypair()
  await keypair.initialize()

  const suite = new Ed25519Signature(keypair)
  const credential: PlainDocument = {
    "@context": "https://w3id.org/security/v2",
    "type": "sec:BbsBlsSignature2020",
    "created": "2024-12-16T12:05:38Z",
    "verificationMethod": "did:example:489398593#test",
    "proofPurpose": "assertionMethod",
  }

  const purpose = new Purpose("assertionMethod")
  const proof = await suite.createProof(credential, { purpose, loader: loader })

  const a = await canonize(credential, {
    algorithm: "URDNA2015",
    format: "application/n-quads",
    documentLoader: loader,
    skipExpansion: false,
  })
  console.log(a)
})
