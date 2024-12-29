import { assert } from "@std/assert/assert"
import {
  canonize,
  concatenate,
  type PlainDocument,
  type Proof,
  Purpose,
  sha256,
  toW3CTimestampString,
} from "@crumble-jon/ld-crypto-syntax"

import { Ed25519Keypair } from "../src/keypair/keypair.ts"
import { sign, verify } from "../src/suite/core.ts"
import { loader } from "./loader.ts"
import { Ed25519Signature } from "../src/suite/signature.ts"

Deno.test("core signing and verifying", async () => {
  const keypair = new Ed25519Keypair()
  await keypair.initialize()

  const message = new Uint8Array(1024)
  crypto.getRandomValues(message)

  const signature = await sign(message, keypair.privateKey)
  const result = await verify(message, signature, keypair.publicKey)

  console.log("signature:", signature)
  assert(result.verified)
})

Deno.test("basic signing and verifying", async () => {
  const keypair = new Ed25519Keypair()
  await keypair.initialize()

  const credential: PlainDocument = {
    "@context": [
      "https://www.w3.org/ns/credentials/v2",
      "https://www.w3.org/ns/credentials/examples/v2",
    ],
    "id": "http://university.example/credentials/58473",
    "type": ["VerifiableCredential", "ExampleAlumniCredential"],
    "issuer": "did:example:1145141919810",
    "validFrom": "2010-01-01T00:00:00Z",
    "credentialSubject": {
      "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
      "alumniOf": {
        "id": "did:example:c276e12ec21ebfeb1f712ebc6f1",
        "name": "Example University",
      },
    },
  }

  const proof: Proof = {
    "@context": "https://www.w3.org/ns/credentials/v2",
    type: "DataIntegrityProof",
    cryptosuite: "Ed25519Signature2020",
    proofPurpose: "assertionMethod",
    created: toW3CTimestampString(new Date()),
    proofValue: undefined,
  }

  const canonizedDocument = await canonize(credential, {
    algorithm: "URDNA2015",
    format: "application/n-quads",
    documentLoader: loader,
    skipExpansion: false,
  })

  console.log(proof)

  const canonizedProof = await canonize(proof, {
    algorithm: "URDNA2015",
    format: "application/n-quads",
    documentLoader: loader,
    skipExpansion: false,
  })

  const hashedDocument = await sha256(canonizedDocument)
  const hashedProof = await sha256(canonizedProof)
  const verifyData = concatenate(hashedDocument, hashedProof)
  proof.proofValue = await sign(verifyData, keypair.privateKey)

  const signature = proof.proofValue
  delete proof.proofValue

  console.log(proof)

  const recoveredCanonizedProof = await canonize(proof, {
    algorithm: "URDNA2015",
    format: "application/n-quads",
    documentLoader: loader,
    skipExpansion: false,
  })

  const recoveredHashedProof = await sha256(recoveredCanonizedProof)
  const recoveredVerifyData = concatenate(hashedDocument, recoveredHashedProof)

  console.log(verifyData)
  console.log(recoveredVerifyData)

  const result = await verify(recoveredVerifyData, signature, keypair.publicKey)

  console.log(result)
})

Deno.test("ensemble signing and verifying", async () => {
  const keypair = new Ed25519Keypair()
  await keypair.initialize()

  const credential: PlainDocument = {
    "@context": [
      "https://www.w3.org/ns/credentials/v2",
      "https://www.w3.org/ns/credentials/examples/v2",
    ],
    "id": "http://university.example/credentials/58473",
    "type": ["VerifiableCredential", "ExampleAlumniCredential"],
    "issuer": "did:example:1145141919810",
    "validFrom": "2010-01-01T00:00:00Z",
    "credentialSubject": {
      "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
      "alumniOf": {
        "id": "did:example:c276e12ec21ebfeb1f712ebc6f1",
        "name": "Example University",
      },
    },
  }

  const suite = new Ed25519Signature(keypair)
  const purpose = new Purpose("assertionMethod")
  const proof = await suite.createProof(credential, { purpose, loader })
  console.log(proof)

  const result = await suite.verifyProof(credential, proof, { purpose, loader })
  console.log(result)
})
