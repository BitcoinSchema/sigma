---
description: A digital signature scheme for signing Bitcoin transaction data.
---

# Sigma Protocol

<figure><img src="images/SIGMA.svg" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
This repo contains the SIGMA protocol specification, and a node library for signing and verifying bsv-wasm transactions. See the [Library usage documentation](sigma-library.md) for more information. These docs are best viewed via [GitBook](https://docs.sigmaidentity.com).
{% endhint %}

### Abstract

In an increasingly adversarial digital world, the importance of identity verification and secure transactions has become paramount. The Sigma Protocol is designed to enhance transaction security by signing custom output scripts in blockchain transactions. This paper proposes a protocol that addresses replay attack concerns by incorporating an input transaction ID (txid) and output data hashes into the signature process to strengthen identity verification in blockchain transactions.

### Introduction

As the digital landscape continues to evolve, establishing and maintaining trust in online transactions has become increasingly challenging. In response, the blockchain community has been developing solutions to tackle issues such as identity verification and transaction security. One such solution is the Sigma Protocol, which enables users to sign custom output scripts in blockchain transactions, asserting the authorship and integrity of the data. This paper presents the Sigma Protocol designed to cover custom output scripts and mitigate potential replay attacks.

### The Sigma Protocol

The Sigma Protocol is designed to sign custom output scripts by appending a few fields of data after the data being signed in the transaction output script. The protocol has the following structure:

```
<locking script>
OP_RETURN
  [Additional Data]
  |
  SIGMA
  [Signing Algorithm]
  [Signing Address]
  [Signature]
  [VIN]
```

Here's a brief explanation of the fields:

* `Additional Data`: The OP\_RETURN data you want to sign. Optional. If present, this library will add a protocol separator character "|" which is not signed. If absent, the library will add "OP\_RETURN" to the script, followed by the SIGMA protocol fields.
* `Signing Algorithm`: The algorithm used for signing, in this case, "ECDSA" for Standard ECDSA Message Signing using SHA256 as the digest. No other algorithms are currently supported by the library.
* `Signing Address`: The P2PKH address derived from the public key of the signer. If using Bitcoin Attestation Protocol to sign with an existing on-chain identity, this should be derived from your current signing key.
* `Signature`: The Sigma signature generated using the private key corresponding to the signing address. You will see the signature in hex format in Bitcoin scripts, but the library will return this field in Base64 format for the sake of consistency with other signing schemes.
* `VIN` : The input to reference by index. The txid of this input will be incorporated into the signature. If a -1 is specified, it indicated the corresponding input will be signed.
