import * as SUITE_2020 from "../../data/contexts/ed25519-2020.json" with { type: "json" }
import * as JWS_2020 from "../../data/contexts/jws-v1.json" with { type: "json" }
import * as CREDENTIAL_EXAMPLE_V2 from "../../data/contexts/example-v2.json" with { type: "json" }

import * as CONTEXT_URL from "./constants.ts"

export const URL_CONTEXT_MAP: Map<string, object> = new Map<string, object>([
  [CONTEXT_URL.SUITE_2020, SUITE_2020.default],
  [CONTEXT_URL.JWS_2020, JWS_2020.default],
  [CONTEXT_URL.CREDENTIAL_EXAMPLE_V2, CREDENTIAL_EXAMPLE_V2.default],
])
