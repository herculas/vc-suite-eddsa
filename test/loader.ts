import { extend, type Loader } from "@crumble-jon/ld-crypto-syntax"

import * as security from "../data/contexts/security-v2.json" with { type: "json" }
import * as controller from "../data/test/controller.json" with { type: "json" }
import * as keypair from "../data/test/keypair.json" with { type: "json" }

export const customLoader: Loader = (url: string) => {
  const document = new Map<string, object>([
    ["did:example:489398593#test", keypair.default],
    ["did:example:489398593", controller.default],
    ["https://w3id.org/security/v2", security.default],
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
