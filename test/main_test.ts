import { generateRawKeypair } from "../src/key/core.ts"

Deno.test("string prefix", async () => {
  const a = await generateRawKeypair()
  console.log(a)
})
