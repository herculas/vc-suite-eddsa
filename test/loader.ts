import { extend, type Loader, type URI } from "@crumble-jon/ld-crypto-syntax"

import * as KEYPAIR from "../data/test/keypair.json" with { type: "json" }

export const customLoader: Loader = (url: URI) => {
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
}

export const loader = extend(customLoader)
