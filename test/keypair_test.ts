import { assert, assertEquals } from "@std/assert"

import { generateKeypair, jwkToKey, keyToJwk } from "../src/keypair/core.ts"
import { Ed25519Keypair } from "../src/keypair/keypair.ts"

Deno.test("key gen", async () => {
  const keypair = await generateKeypair()
  console.log(keypair)
})

Deno.test("fingerprint", async () => {
  const keypair = new Ed25519Keypair()
  await keypair.initialize()
  const fingerprint = await keypair.generateFingerprint()
  const result = await keypair.verifyFingerprint(fingerprint)
  assert(result.verified)
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

  console.log(jwkPrivate2)
  jwkPrivate2.d = undefined
  jwkPrivate2.key_ops = ["verify"]

  const recoveredPublic2 = await jwkToKey(jwkPrivate2, "public")
  console.log(recoveredPublic2)
})

Deno.test("Ed25519 keypair export", async () => {
  const keypair = new Ed25519Keypair()
  keypair.controller = "did:example:489398593"
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
  keypair.controller = "did:example:489398593"
  await keypair.initialize()

  const jwkPrivate = await keypair.export({ type: "jwk", flag: "private" })
  const jwkPublic = await keypair.export({ type: "jwk", flag: "public" })

  const recoveredPublicOnly = await Ed25519Keypair.import(jwkPublic, { type: "jwk" }) as Ed25519Keypair
  console.log(recoveredPublicOnly.publicKey)

  const recoveredBoth = await Ed25519Keypair.import(jwkPrivate, { type: "jwk" }) as Ed25519Keypair
  console.log(recoveredBoth.privateKey)
  console.log(recoveredBoth.publicKey)
})

Deno.test("Ed25519 keypair import 2: multibase", async () => {
  const keypair = new Ed25519Keypair()
  keypair.controller = "did:example:489398593"
  await keypair.initialize()

  const multibasePrivate = await keypair.export({ type: "multibase", flag: "private" })
  const multibasePublic = await keypair.export({ type: "multibase", flag: "public" })

  const recoveredPublicOnly = await Ed25519Keypair.import(multibasePublic, { type: "multibase" }) as Ed25519Keypair
  console.log(recoveredPublicOnly.publicKey)

  const recoveredBoth = await Ed25519Keypair.import(multibasePrivate, { type: "multibase" }) as Ed25519Keypair
  console.log(recoveredBoth.privateKey)
  console.log(recoveredBoth.publicKey)
})
