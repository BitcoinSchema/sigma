# Sigma Library

### Library Usage

To use the Sigma Protocol library, follow the instructions below:

1. Install the library using npm:

```bash
yarn add sigma-protocol
```

2. You can use the `verify` method to check a signature:

```javascript
import { Sigma } from "sigma-protocol";
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

4. Use the `verify` method to verify the signature:

```javascript
const sigma = new Sigma(tx);

const isValid = sigma.verify()

console.log("Signature is valid:", isValid);
```

You can select a transaction output, and sigma instance to target. If you do not specify a target, the first output and first sigma instance will be assumed.

Here we target output index 1:

```javascript
const sigma = new Sigma(tx, 1);
```

Here we target output index 1, sigma instance 2:

```javascript
// this means there are 2 signatures on a single output
// this is typical when a user signs, and then a 
// platform signs covering the user signature
const sigma = new Sigma(tx, 1);
```

Once an instance is targeted, you can use verify like normal:

```javascript
  const isValid = sigma.verify()
  console.log("Signature is valid:", isValid);
```

If you sign a tx and the sign it a again the signature will be replaced. However, you can add additional signatures by incrementing the sigma instance number before signing.

```javascript
  const sigma = new Sigma(tx, 1, 2);
  sigma.sign(privateKey);
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
