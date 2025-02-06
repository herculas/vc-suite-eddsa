import type { ErrorCode } from "./constants.ts"

export class SuiteError extends Error {
  code: ErrorCode

  constructor(_code: ErrorCode, _name: string, _message: string) {
    super(_message)
    this.code = _code
    this.name = _name
    this.message = _message
  }
}