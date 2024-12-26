import type { SuiteErrorCode } from "./constants.ts"

export class SuiteError extends Error {
  code: SuiteErrorCode

  constructor(_code: SuiteErrorCode, _name: string, _message: string) {
    super(_message)
    this.code = _code
    this.name = _name
    this.message = _message
  }
}