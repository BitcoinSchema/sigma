---
description: A digital signature scheme for signing Bitcoin transaction data.
---

# Sigma Protocol

### Abstract

In an increasingly adversarial digital world, the importance of identity verification and secure transactions has become paramount. The Sigma Protocol is designed to enhance transaction security by signing custom output scripts in blockchain transactions. This paper proposes a protocol that addresses replay attack concerns by incorporating input transaction IDs (txids) and output data hashes into the signature process, effectively strengthening the identity verification in blockchain transactions.

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
```

Here's a brief explanation of the fields:

* `Additional Data`: The OP\_RETURN data you want to sign. Optional. If present, this library will add a protocol separator character "|" which is not signed. If absent, the library will add "OP\_RETURN" to the script, followed by the SIGMA protocol fields.
* `Signing Algorithm`: The algorithm used for signing, in this case, "BSM" for Bitcoin Signed Message. No other algorithms are currently supported by the library.
* `Signing Address`: The P2PKH address derived from the public key of the signer. If using Bitcoin Attestation Protocol to sign with an existing on-chain identity, this should be derived from your current signing key.
* `Signature`: The Sigma signature generated using the private key corresponding to the signing address. You will see the signature in hex format in Bitcoin scripts, but the library will return this field in Base64 format for the sake of consistency with other signing schemes.

### Library Usage

To use the Sigma Protocol library, follow the instructions below:

1. Install the library using npm:

```bash
yarnl <sigma-protocol>
```

2. Import the `sign` and `verifySignature` functions from the library:

```javascript
import { sign, verifySignature } from "sigma-protocol";
```

3. Use the `sign` function to sign your data:

```javascript
const privateKeyWIF = "L1rWWk8Jv3q6ZKd6ZJ2WVFHN8vZurA9wm1DcoepakHFp8z8kY7YJ"; // Replace this with your private key
const inputTxIds = ["txid1", "txid2"];
const data = Buffer.concat(
  ["pushdata1", "pushdata2"].map((pushdata) => Buffer.from(pushdata))
);

const { signingAddress, signature } = sign(privateKeyWIF, inputTxIds, data);
console.log("Signing address:", signingAddress);
console.log("Signature:", signature);
```

4. Use the `verifySignature` function to verify the signature:

```javascript
const isValid = verifySignature(
  signingAddress,
  "BSM",
  signature,
  inputTxIds,
  data
);
console.log("Signature is valid:", isValid);
```

### Building the Library:

To build the Sigma Protocol library yourself, follow these steps:

1. Clone the repository:

```bash
git clone https://github.com/BitcoinSchema/sigma-protocol.git
```

2. Navigate to the project directory and install dependencies:

```bash
cd sigma-protocol
yarn
```

3. Build the library:

```bash
yarn build
```

The compiled JavaScript files will be output to the `./dist` directory.
