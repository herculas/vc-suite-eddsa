# Verifiable Credential Cryptosuite (EdDSA)

[![Release](https://github.com/herculas/vc-suite-eddsa/actions/workflows/release.yml/badge.svg)](https://github.com/herculas/vc-suite-eddsa/actions/workflows/release.yml)
[![JSR](https://jsr.io/badges/@herculas/vc-suite-eddsa)](https://jsr.io/@herculas/vc-suite-eddsa)
[![JSR Score](https://jsr.io/badges/@herculas/vc-suite-eddsa/score)](https://jsr.io/@herculas/vc-suite-eddsa)

EdDSA cryptographic suite for linked data files. The interface is compatible with the W3C specification of
[JSON-LD](https://www.w3.org/TR/json-ld11/), [Verifiable Credentials](https://www.w3.org/TR/vc-data-model-2.0/),
[Verifiable Credential Data Integrity](https://www.w3.org/TR/vc-data-integrity/) and
[EdDSA Cryptosuite](https://www.w3.org/TR/vc-di-eddsa/).

## Introduction

EdDSA cryptosuite can be used to provide integrity and authenticity guarantees for linked data files. This package is
designed to provide the EdDSA cryptographic suite. This suite SHOULD be used with the
[vc-data-integrity](https://jsr.io/@herculas/vc-data-integrity) framework.

## Getting started

To use this package within your own Deno project, run:

```shell
deno add jsr:@herculas/vc-suite-eddsa
```

## Usage

### Keypair operations

#### Generate and initialize keypair instances

Initialize an Ed25519 keypair instance, and generate a keypair.

```js
const keypair = new Ed25519Keypair()
keypair.controller = "did:example:1145141919810"
await keypair.initialize()
```

#### Export keypair instances

Export an Ed25519 keypair instance to a verification method, which could further be encapsulated in a controlled
identifier document (e.g., a DID document).

```js
const method = await keypair.export({ type: "JsonWebKey", flag: "private" })
```

The `export()` method accepts an `options` object as parameter, which should contain `type` and `flag` fields. The
`type` field specifies the key format in the exported verification method, offering two options: `Multikey` or
`JsonWebKey`. The `flag` parameter specifies whether to export the private or public key-if the specified key is not
present in the current keypair instance, an error will be raised. Notably, when `flag` is set to `private` and the
keypair instance contains both public and private keys, the system automatically exports the public key alongside the
private key.

Here is an example of the exported verification method:

```json
{
  "id": "did:example:1145141919810#eE700u33DYIS0Gnm8UUNNwxnMhknV53I7piF2ciBZDM",
  "type": "JsonWebKey",
  "controller": "did:example:1145141919810",
  "secretKeyJwk": {
    "kty": "OKP",
    "use": "sig",
    "key_ops": ["sign"],
    "alg": "Ed25519",
    "ext": true,
    "crv": "Ed25519",
    "x": "38sLe-pQmQF-Bn7XPdP9LlWQIxhUCuE0HqFYHBFoX74",
    "y": "",
    "d": "jsKu-dEUpTmXAKLRoJbUd4EsIEbm0sNICbN4tjUTmXs"
  },
  "publicKeyJwk": {
    "kty": "OKP",
    "use": "sig",
    "key_ops": ["verify"],
    "alg": "Ed25519",
    "ext": true,
    "crv": "Ed25519",
    "x": "38sLe-pQmQF-Bn7XPdP9LlWQIxhUCuE0HqFYHBFoX74",
    "y": ""
  }
}
```

#### Import keypair instances from external verification methods

Externally obtained verification methods can also be imported into keypair instances:

```js
const recoveredKeypair = await Ed25519Keypair.import(method)
```

The `import()` method accepts an optional `options` parameter, containing three optional fields:

- `checkContext`: a `boolean` indicating whether to check the `@context` field of the imported document. Defaults to
  `false`.
- `checkExpired`: a `boolean` indicating whether to check if the imported document has expired. Defaults to `false`.
- `checkRevoked`: a `boolean` indicating whether to check if the keys contained in the imported document have been
  revoked. Defaults to `false`.

#### Encapsulate the verification method

The exported verification method could be encapsulated in a controlled identifier document (e.g., a DID document), which
could further be used for proof generation and verification. The verification method can either be directly wrapped to
generate a new document, or added to an existing document by passing the document as the second parameter of
`encapsulateVerificationMethod` function.

```js
import { document } from "@herculas/vc-data-integrity"

const cidDocument = document.encapsulateVerificationMethod(
  method,
  undefined,
  new Set(["assertionMethod"]),
)
```

The third parameter of the function specifies the verification relationship, please refer to
[Controlled Identifiers](https://www.w3.org/TR/cid/#verification-relationships). The generated controlled identifier
document looks like:

```json
{
  "@context": "https://www.w3.org/ns/cid/v1",
  "id": "did:example:1145141919810",
  "verificationMethod": [
    {
      "id": "did:example:1145141919810#eE700u33DYIS0Gnm8UUNNwxnMhknV53I7piF2ciBZDM",
      "type": "JsonWebKey",
      "controller": "did:example:1145141919810",
      "secretKeyJwk": {
        "kty": "OKP",
        "use": "sig",
        "key_ops": ["sign"],
        "alg": "Ed25519",
        "ext": true,
        "crv": "Ed25519",
        "x": "38sLe-pQmQF-Bn7XPdP9LlWQIxhUCuE0HqFYHBFoX74",
        "y": "",
        "d": "jsKu-dEUpTmXAKLRoJbUd4EsIEbm0sNICbN4tjUTmXs"
      },
      "publicKeyJwk": {
        "kty": "OKP",
        "use": "sig",
        "key_ops": ["verify"],
        "alg": "Ed25519",
        "ext": true,
        "crv": "Ed25519",
        "x": "38sLe-pQmQF-Bn7XPdP9LlWQIxhUCuE0HqFYHBFoX74",
        "y": ""
      }
    }
  ],
  "assertionMethod": [
    "did:example:1145141919810#eE700u33DYIS0Gnm8UUNNwxnMhknV53I7piF2ciBZDM"
  ]
}
```

### Data integrity proof

Compatible with the [EdDSA Cryptosuite](https://www.w3.org/TR/vc-di-eddsa/) specification, this library provides two
cryptographic suites: `eddsa-rdfc-2022` and `eddsa-jcs-2022`. Next, we use `eddsa-rdfc-2022` as a demonstration example,
as operations with `eddsa-jcs-2022` are essentially the same.

#### Generating proofs

The following is the document that needs to be proven:

```js
const unsecuredCredential: Credential = {
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://www.w3.org/ns/credentials/examples/v2",
  ],
  "id": "urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33",
  "type": ["VerifiableCredential", "AlumniCredential"],
  "name": "Alumni Credential",
  "description": "A minimum viable example of an Alumni Credential.",
  "issuer": "https://vc.example/issuers/5678",
  "validFrom": "2023-01-01T00:00:00Z",
  "credentialSubject": {
    "id": "did:example:abcdefgh",
    "alumniOf": "The School of Examples",
  },
}
```

To prove this, first construct a `proofOptions` object that contains some metadata for generating the proof. Please note
that the `verificationMethod` in the `proofOptions` should be a valid URL or DID, which will be used to index the
verification method for generating and validating proofs.

```js
const proofOptions: Proof = {
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
  ],
  "type": "DataIntegrityProof",
  "cryptosuite": "eddsa-rdfc-2022",
  "created": "2025-01-24T23:36:38Z",
  "proofPurpose": "assertionMethod",
  "verificationMethod": "did:example:1145141919810#eE700u33DYIS0Gnm8UUNNwxnMhknV53I7piF2ciBZDM"
}
```

Next, a proof is generated for the given `unsecuredDocument` and `proofOptions`. Note that the `createProof()` method
accepts a `documentLoader` function as a parameter, which loads external files needed for proof generation—including
JSON-LD Context files and the verification method containing key materials.

```js
const proof = await EddsaRdfc2022.createProof(
  unsecuredCredential,
  {
    proof: proofOptions,
    documentLoader: testLoader,
  },
)
```

The resulting `proof` is:

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2"
  ],
  "type": "DataIntegrityProof",
  "cryptosuite": "eddsa-rdfc-2022",
  "created": "2025-01-24T23:36:38Z",
  "verificationMethod": "did:example:1145141919810#eE700u33DYIS0Gnm8UUNNwxnMhknV53I7piF2ciBZDM",
  "proofPurpose": "assertionMethod",
  "proofValue": "z2YwC8z3ap7yx1nZYCg4L3j3ApHsF8kgPdSb5xoS1VR7vPG3F561B52hYnQF9iseabecm3ijx4K1FBTQsCZahKZme"
}
```

#### Verifying proofs

The following is a document secured by a data integrity proof.

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://www.w3.org/ns/credentials/examples/v2"
  ],
  "id": "urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33",
  "type": ["VerifiableCredential", "AlumniCredential"],
  "name": "Alumni Credential",
  "description": "A minimum viable example of an Alumni Credential.",
  "issuer": "https://vc.example/issuers/5678",
  "validFrom": "2023-01-01T00:00:00Z",
  "credentialSubject": {
    "id": "did:example:abcdefgh",
    "alumniOf": "The School of Examples"
  },
  "proof": {
    "@context": [
      "https://www.w3.org/ns/credentials/v2"
    ],
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-rdfc-2022",
    "created": "2025-01-24T23:36:38Z",
    "verificationMethod": "did:example:1145141919810#eE700u33DYIS0Gnm8UUNNwxnMhknV53I7piF2ciBZDM",
    "proofPurpose": "assertionMethod",
    "proofValue": "z2YwC8z3ap7yx1nZYCg4L3j3ApHsF8kgPdSb5xoS1VR7vPG3F561B52hYnQF9iseabecm3ijx4K1FBTQsCZahKZme"
  }
}
```

The following `verifyProof` method verifies whether the `proof` field contained in the above document ensures the
document's authenticity and integrity.

```js
const result = await EddsaRdfc2022.verifyProof(securedCredential, { documentLoader: testLoader })
```

The `result` should be:

```json
{
  "verified": true,
  "verifiedDocument": {
    "@context": [
      "https://www.w3.org/ns/credentials/v2",
      "https://www.w3.org/ns/credentials/examples/v2"
    ],
    "id": "urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33",
    "type": ["VerifiableCredential", "AlumniCredential"],
    "name": "Alumni Credential",
    "description": "A minimum viable example of an Alumni Credential.",
    "issuer": "https://vc.example/issuers/5678",
    "validFrom": "2023-01-01T00:00:00Z",
    "credentialSubject": {
      "id": "did:example:abcdefgh",
      "alumniOf": "The School of Examples"
    }
  }
}
```
