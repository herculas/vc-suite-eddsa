import * as SUITE_2020 from "../../data/contexts/ed25519-2020.json" with { type: "json" }
import * as JWS_2020 from "../../data/contexts/jws-v1.json" with { type: "json" }

import * as CONTEXT_URL from "./url.ts"

export const URL_CONTEXT_MAP: Map<string, object> = new Map<string, object>([
  [CONTEXT_URL.SUITE_2020, SUITE_2020.default],
  [CONTEXT_URL.JWS_2020, JWS_2020.default],
])
