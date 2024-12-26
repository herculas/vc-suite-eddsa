import { assertEquals, assert } from "@std/assert"

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

// Deno.test("key export and import", async () => {
//   const keypair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]) as CryptoKeyPair
//   const exportedPrivateKey = await crypto.subtle.exportKey("pkcs8", keypair.privateKey)
//   const typedExportedPrivateKey = new Uint8Array(exportedPrivateKey)
//   console.log(typedExportedPrivateKey)

//   const importedPrivateKey = await crypto.subtle.importKey(
//     "pkcs8",
//     typedExportedPrivateKey,
//     "Ed25519",
//     true,
//     ["sign"],
//   ) as CryptoKey
//   const reExportedPrivateKey = await crypto.subtle.exportKey("pkcs8", importedPrivateKey)
//   const typedReExportedPrivateKey = new Uint8Array(reExportedPrivateKey)
//   console.log(typedReExportedPrivateKey)

//   assertEquals(typedExportedPrivateKey, typedReExportedPrivateKey)

//   const jwkPrivateKey = await crypto.subtle.exportKey("jwk", keypair.privateKey)
//   console.log(jwkPrivateKey)
// })
