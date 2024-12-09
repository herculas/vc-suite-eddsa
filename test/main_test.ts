import { generateRawKeypair } from "../src/key/core.ts"
import { ED25519Keypair } from "../src/key/keypair.ts"

Deno.test("string prefix", () => {
  const a = generateRawKeypair()
  console.log(a)
})

Deno.test("key gen", () => {
  const keypair = new ED25519Keypair()
  keypair.generate()
  const a = keypair.export(true, false)
  console.log(a)
})
