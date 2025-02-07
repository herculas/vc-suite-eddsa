import { assert, assertEquals } from "@std/assert"

import { generateKeypair, jwkToKey, keyToJwk } from "../src/key/core.ts"
import { Ed25519Keypair } from "../src/key/keypair.ts"

import * as TEST_KEYPAIR from "./mock/keypair.json" with { type: "json" }

Deno.test("key gen", async () => {
  const keypair = await generateKeypair()
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
  const keypair = await generateKeypair()

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

  const jwkPrivate = await keypair.export({ type: "jwk", flag: "private" })
  const jwkPublic = await keypair.export({ type: "jwk", flag: "public" })

  const multibasePrivate = await keypair.export({ type: "multibase", flag: "private" })
  const multibasePublic = await keypair.export({ type: "multibase", flag: "public" })

  console.log(jwkPrivate)
  console.log(jwkPublic)
  console.log(multibasePrivate)
  console.log(multibasePublic)
})

Deno.test("Ed25519 keypair import 1: json web key", async () => {
  const keypair = new Ed25519Keypair()
  keypair.controller = "did:example:1145141919810"
  await keypair.initialize()

  const jwkPrivate = await keypair.export({ type: "jwk", flag: "private" })
  const jwkPublic = await keypair.export({ type: "jwk", flag: "public" })
  console.log(jwkPrivate)
  console.log(jwkPublic)

  const recoveredPublicOnly = await Ed25519Keypair.import(jwkPublic, { type: "jwk" }) as Ed25519Keypair
  console.log(recoveredPublicOnly.publicKey)

  const recoveredBoth = await Ed25519Keypair.import(jwkPrivate, { type: "jwk" }) as Ed25519Keypair
  console.log(recoveredBoth.privateKey)
  console.log(recoveredBoth.publicKey)
})

Deno.test("Ed25519 keypair import 2: multibase", async () => {
  const keypair = new Ed25519Keypair()
  keypair.controller = "did:example:1145141919810"
  await keypair.initialize()

  const multibasePrivate = await keypair.export({ type: "multibase", flag: "private" })
  const multibasePublic = await keypair.export({ type: "multibase", flag: "public" })
  console.log(multibasePrivate)
  console.log(multibasePublic)

  const recoveredPublicOnly = await Ed25519Keypair.import(multibasePublic, { type: "multibase" }) as Ed25519Keypair
  console.log(recoveredPublicOnly.publicKey)

  const recoveredBoth = await Ed25519Keypair.import(multibasePrivate, { type: "multibase" }) as Ed25519Keypair
  console.log(recoveredBoth.privateKey)
  console.log(recoveredBoth.publicKey)
})

Deno.test("Ed25519 keypair import 3: json", async () => {
  const recoveredKey = await Ed25519Keypair.import(TEST_KEYPAIR.default, { type: "multibase" }) as Ed25519Keypair

  const data = crypto.getRandomValues(new Uint8Array(128))
  const signature = await crypto.subtle.sign("Ed25519", recoveredKey.privateKey!, data)
  const verification = await crypto.subtle.verify("Ed25519", recoveredKey.publicKey!, signature, data)
  assert(verification)
})
