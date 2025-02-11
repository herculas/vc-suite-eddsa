import { decodeBase58, decodeBase64Url, encodeBase58, encodeBase64Url } from "@std/encoding"
import { ImplementationError, ImplementationErrorCode } from "@herculas/vc-data-integrity"

import * as PREFIX_CONSTANT from "../constant/prefix.ts"

export class base58btc {
  static encode(data: Uint8Array): string {
    return PREFIX_CONSTANT.BASE_58_BTC + encodeBase58(data)
  }

  static decode(data: string): Uint8Array {
    if (!data.startsWith(PREFIX_CONSTANT.BASE_58_BTC)) {
      throw new ImplementationError(
        ImplementationErrorCode.DECODING_ERROR,
        "encode/base58::decode",
        "Invalid base-58-btc prefix!",
      )
    }
    return decodeBase58(data.slice(PREFIX_CONSTANT.BASE_58_BTC.length))
  }
}

export class base64url {
  static encode(data: Uint8Array): string {
    return encodeBase64Url(data)
  }

  static decode(data: string): Uint8Array {
    return decodeBase64Url(data)
  }
}
