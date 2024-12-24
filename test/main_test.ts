import { generateRawKeypair } from "../src/keypair/core.ts"
import { Ed25519Keypair } from "../src/keypair/keypair.ts"

Deno.test("key gen", async () => {
  const a = await generateRawKeypair()
  console.log(a)
})

Deno.test("key gen 2", async () => {
  const keypair = new Ed25519Keypair()
  await keypair.generate()

  console.log(keypair.privateKeyMultibase)
  console.log(keypair.publicKeyMultibase)
})
