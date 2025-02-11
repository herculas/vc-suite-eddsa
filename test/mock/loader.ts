import { type JsonLdDocument, loader } from "@herculas/vc-data-integrity"

import * as CID_FILE from "./cid.json" with { type: "json" }
import * as CITIZENSHIP from "./context-citizenship.json" with { type: "json" }

export const testLoader = loader.extend((url) => {
  const document = new Map<string, JsonLdDocument>([
    ["did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2", CID_FILE.default],
    ["https://w3id.org/citizenship/v4rc1", CITIZENSHIP.default],
  ])

  if (document.has(url)) {
    return Promise.resolve({
      documentUrl: url,
      document: document.get(url)!,
    })
  }
  throw new Error(
    `Attempted to remote load context : '${url}', please cache instead`,
  )
})
