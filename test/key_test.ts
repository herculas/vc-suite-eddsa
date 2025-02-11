import { assert, assertEquals, assertExists } from "@std/assert"
import type { CIDDocument } from "@herculas/vc-data-integrity"

import { Ed25519Keypair } from "../src/key/keypair.ts"
import { generateRawKeypair, jwkToKey, keyToJwk } from "../src/key/core.ts"

import * as TEST_CID_DOCUMENT from "./mock/cid.json" with { type: "json" }

Deno.test("fingerprint generation and verification", async () => {
  const keypair = new Ed25519Keypair()
  await keypair.initialize()
  const fingerprint = await keypair.generateFingerprint()
  const result = await keypair.verifyFingerprint(fingerprint)
  assert(result)
})

Deno.test("Keypair import and export: raw functions", async () => {
  const keypair = await generateRawKeypair()

  const jwkPrivate = await keyToJwk(keypair.privateKey, "private")
  const jwkPublic = await keyToJwk(keypair.publicKey, "public")

  const recoveredPrivate = await jwkToKey(jwkPrivate, "private")
  const recoveredPublic = await jwkToKey(jwkPublic, "public")

  const jwkPrivate2 = await keyToJwk(recoveredPrivate, "private")
  const jwkPublic2 = await keyToJwk(recoveredPublic, "public")

  assertEquals(jwkPrivate, jwkPrivate2)
  assertEquals(jwkPublic, jwkPublic2)
})

Deno.test("Keypair export: encapsulated", async () => {
  const keypair = new Ed25519Keypair()
  keypair.controller = "did:example:1145141919810"
  await keypair.initialize()

  const jwkPrivate = await keypair.export({ type: "JsonWebKey", flag: "private" })
  const jwkPublic = await keypair.export({ type: "JsonWebKey", flag: "public" })

  const multibasePrivate = await keypair.export({ type: "Multikey", flag: "private" })
  const multibasePublic = await keypair.export({ type: "Multikey", flag: "public" })

  console.log(jwkPrivate)

  assertExists(jwkPrivate)
  assertExists(jwkPublic)
  assertExists(multibasePrivate)
  assertExists(multibasePublic)
})

Deno.test("Keypair export and import: JSON Web Key", async () => {
  const keypair = new Ed25519Keypair()
  keypair.controller = "did:example:1145141919810"
  await keypair.initialize()

  const jwkPrivate = await keypair.export({ type: "JsonWebKey", flag: "private" })
  const jwkPublic = await keypair.export({ type: "JsonWebKey", flag: "public" })

  const recoveredPublicOnly = await Ed25519Keypair.import(jwkPublic)
  const recoveredBoth = await Ed25519Keypair.import(jwkPrivate)

  assertExists(recoveredPublicOnly.publicKey)
  assertExists(recoveredBoth.privateKey)
  assertExists(recoveredBoth.publicKey)
})

Deno.test("Keypair export and import: Multibase", async () => {
  const keypair = new Ed25519Keypair()
  keypair.controller = "did:example:1145141919810"
  await keypair.initialize()

  const multibasePrivate = await keypair.export({ type: "Multikey", flag: "private" })
  const multibasePublic = await keypair.export({ type: "Multikey", flag: "public" })

  const recoveredPublicOnly = await Ed25519Keypair.import(multibasePublic)
  const recoveredBoth = await Ed25519Keypair.import(multibasePrivate)

  assertExists(recoveredPublicOnly.publicKey)
  assertExists(recoveredBoth.privateKey)
  assertExists(recoveredBoth.publicKey)
})

Deno.test("Keypair import and verification", async () => {
  const cid = TEST_CID_DOCUMENT.default as CIDDocument
  const method = cid.verificationMethod![0]
  const recoveredKey = await Ed25519Keypair.import(method)

  const data = crypto.getRandomValues(new Uint8Array(128))
  const signature = await crypto.subtle.sign("Ed25519", recoveredKey.privateKey!, data)
  const result = await crypto.subtle.verify("Ed25519", recoveredKey.publicKey!, signature, data)

  assert(result)
})
