import * as KEYPAIR from "./keypair.json" with { type: "json" }

export const testLoader = extend((url) => {
  const document = new Map<string, object>([
    ["did:example:1145141919810", KEYPAIR.default],
  ])

  if (document.has(url)) {
    const context = document.get(url)!
    return Promise.resolve({
      document: context,
      documentUrl: url,
    })
  }
  throw new Error(
    `Attempted to remote load context : '${url}', please cache instead`,
  )
})
