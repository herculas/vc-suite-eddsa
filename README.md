# vc-suite-ed25519

[![Release](https://github.com/herculas/vc-suite-ed25519/actions/workflows/release.yml/badge.svg)](https://github.com/herculas/vc-suite-ed25519/actions/workflows/release.yml)

Ed25519 cryptographic suite for linked data files. The interface is compatible with the W3C specification of
[JSON-LD](https://www.w3.org/TR/json-ld11/) and [Verifiable Credentials](https://www.w3.org/TR/vc-data-model-2.0/).

## Introduction

Ed25519 signature scheme can be used to provide integrity and authenticity guarantees for linked data files. This
package is designed to provide the Ed25519 cryptographic suite. This suite should be used with the
[vc-data-integrity](https://jsr.io/@herculas/vc-data-integrity) framework.

## Getting started

To use this package within your own Deno project, run:

```shell
deno add jsr:@herculas/vc-suite-ed25519
```

## Usage

### Keypair generation

Initialize an Ed25519 keypair instance, and generate a keypair.

```js
const keypair = new Ed25519Keypair()
await keypair.initialize()
```

### Signing

Initialize an Ed25519 cryptographic suite using the generated keypair, and specify a signature purpose.

```js
const suite = new Ed25519Signature(keypair)
const purpose = new Purpose("assertionMethod")
```

Signing the given JSON-LD document using the generated crypto suite.

```js
const credential: PlainDocument = {
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://www.w3.org/ns/credentials/examples/v2",
  ],
  "id": "http://university.example/credentials/58473",
  "type": ["VerifiableCredential", "ExampleAlumniCredential"],
  "issuer": "did:example:1145141919810",
  "validFrom": "2010-01-01T00:00:00Z",
  "credentialSubject": {
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
    "alumniOf": {
      "id": "did:example:c276e12ec21ebfeb1f712ebc6f1",
      "name": "Example University",
    },
  },
}

const signature = await suite.createProof(credential, { purpose, loader })
```

The resulting document:

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://www.w3.org/ns/credentials/examples/v2"
  ],
  "id": "http://university.example/credentials/58473",
  "type": ["VerifiableCredential", "ExampleAlumniCredential"],
  "issuer": "did:example:1145141919810",
  "validFrom": "2010-01-01T00:00:00Z",
  "credentialSubject": {
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
    "alumniOf": {
      "id": "did:example:c276e12ec21ebfeb1f712ebc6f1",
      "name": "Example University"
    }
  },
  "proof": {
    "type": "DataIntegrityProof",
    "created": "2025-01-17T16:09:46Z",
    "cryptosuite": "Ed25519Signature2020",
    "proofPurpose": "assertionMethod",
    "proofValue": "z2SNaio4aqahtsL7ZyuJAqiA96TjNXHgHsrAZy1EWgcjNXDPUejz2vpZfGNKGMywjLLzGpCfD66HypFpm2E7bcuMJ"
  }
}
```

### Verifying

Verify a Ed25519 signature.

```js
const verification = await suite.verifyProof(credential, proof, { purpose, loader })
```
