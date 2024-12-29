import { extend, type Loader, type URL } from "@crumble-jon/ld-crypto-syntax"

import * as CREDENTIAL_EXAMPLE_V2 from "../data/contexts/example-v2.json" with { type: "json" }
import * as KEYPAIR from "../data/test/keypair.json" with { type: "json" }
import * as CONTROLLER from "../data/test/controller.json" with { type: "json" }

export const customLoader: Loader = (url: URL) => {
  const document = new Map<string, object>([
    ["https://www.w3.org/ns/credentials/examples/v2", CREDENTIAL_EXAMPLE_V2.default],
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
