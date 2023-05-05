---
description: A digital signature scheme for signing Bitcoin transaction data.
---

# Sigma Protocol

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

### Library Usage

To use the Sigma Protocol library, follow the instructions below:

1. Install the library using npm:

```bash
yarn add sigma-protocol
```

2. Import the `sign` and `verifySignature` functions from the library:

```javascript
import { sign, verifySignature } from "sigma-protocol";
```

3. Use the `sign` function to sign your data:

```javascript
const outputScriptAsm = `OP_0 OP_RETURN ${Buffer.from(
  "pushdata1",
  "utf-8"
).toString("hex")} ${Buffer.from("pushdata2", "utf-8").toString("hex")}`;

const script = Script.from_asm_string(outputScriptAsm);

const tx = new Transaction(1, 0);
const txOut = new TxOut(BigInt(0), script);
tx.add_output(txOut);

const sigma = new Sigma(tx);

const { signedTx } = sigma.sign(privateKey);
```

4. Use the `verifySignature` function to verify the signature:

```javascript
const sigma = new Sigma(tx);

const isValid = sigma.verify()

console.log("Signature is valid:", isValid);
```

### Building the Library:

To build the Sigma Protocol library yourself, follow these steps:

1. Clone the repository:

```bash
git clone https://github.com/BitcoinSchema/sigma.git
```

2. Navigate to the project directory and install dependencies:

```bash
cd sigma
yarn
```

3. Build the library:

```bash
yarn build
```

The compiled JavaScript files will be output to the `./dist` directory.
