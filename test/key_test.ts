import { assert, assertEquals, assertExists } from "@std/assert"

import { Ed25519Keypair } from "../src/key/keypair.ts"
import { generateRawKeypair, jwkToKey, keyToJwk } from "../src/utils/key.ts"

import * as TEST_CID_DOCUMENT from "./mock/cid.json" with { type: "json" }

Deno.test("key gen", async () => {
  const keypair = await generateRawKeypair()
  console.log(keypair)
})

Deno.test("fingerprint", async () => {
  const keypair = new Ed25519Keypair()
  await keypair.initialize()
  const fingerprint = await keypair.generateFingerprint()
  const result = await keypair.verifyFingerprint(fingerprint)
  assert(result)
})

Deno.test("jwk import and export", async () => {
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

Deno.test("Ed25519 keypair export", async () => {
  const keypair = new Ed25519Keypair()
  keypair.controller = "did:example:1145141919810"
  await keypair.initialize()

  const jwkPrivate = await keypair.export({ type: "JsonWebKey", flag: "private" })
  const jwkPublic = await keypair.export({ type: "JsonWebKey", flag: "public" })

  const multibasePrivate = await keypair.export({ type: "Multikey", flag: "private" })
  const multibasePublic = await keypair.export({ type: "Multikey", flag: "public" })

  assertExists(jwkPrivate)
  assertExists(jwkPublic)
  assertExists(multibasePrivate)
  assertExists(multibasePublic)
})

Deno.test("Ed25519 keypair import 1: json web key", async () => {
  const keypair = new Ed25519Keypair()
  keypair.controller = "did:example:1145141919810"
  await keypair.initialize()

  const jwkPrivate = await keypair.export({ type: "JsonWebKey", flag: "private" })
  const jwkPublic = await keypair.export({ type: "JsonWebKey", flag: "public" })

  const recoveredPublicOnly = await Ed25519Keypair.import(jwkPublic) as Ed25519Keypair
  const recoveredBoth = await Ed25519Keypair.import(jwkPrivate) as Ed25519Keypair

  assertExists(recoveredPublicOnly.publicKey)
  assertExists(recoveredBoth.privateKey)
  assertExists(recoveredBoth.publicKey)
})

Deno.test("Ed25519 keypair import 2: multibase", async () => {
  const keypair = new Ed25519Keypair()
  keypair.controller = "did:example:1145141919810"
  await keypair.initialize()

  const multibasePrivate = await keypair.export({ type: "Multikey", flag: "private" })
  const multibasePublic = await keypair.export({ type: "Multikey", flag: "public" })

  const recoveredPublicOnly = await Ed25519Keypair.import(multibasePublic) as Ed25519Keypair
  const recoveredBoth = await Ed25519Keypair.import(multibasePrivate) as Ed25519Keypair

  assertExists(recoveredPublicOnly.publicKey)
  assertExists(recoveredBoth.privateKey)
  assertExists(recoveredBoth.publicKey)
})

Deno.test("Ed25519 keypair import 3: from file", async () => {
  const recoveredKey = await Ed25519Keypair.import(TEST_CID_DOCUMENT.default) as Ed25519Keypair
  const data = crypto.getRandomValues(new Uint8Array(128))
  const signature = await crypto.subtle.sign("Ed25519", recoveredKey.privateKey!, data)
  const verification = await crypto.subtle.verify("Ed25519", recoveredKey.publicKey!, signature, data)
  assert(verification)
})
