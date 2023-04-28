import * as assert from "assert";
import { PrivateKey, Script, Transaction, TxOut } from "bsv-wasm";
import { Sigma } from "./";

describe("Sigma Protocol", () => {
  // Test data
  const privateKey = PrivateKey.from_random();

  const outputScriptAsm = `OP_0 OP_RETURN ${Buffer.from(
    "pushdata1",
    "utf-8"
  ).toString("hex")} ${Buffer.from("pushdata2", "utf-8").toString("hex")}`;

  const script = Script.from_asm_string(outputScriptAsm);

  it("signs and verifies a message correctly", () => {
    // Build a simple transaction with the output script
    const tx = new Transaction(1, 0);
    const txOut = new TxOut(BigInt(0), script);
    tx.add_output(txOut);

    // Create a new Sigma instance with the transaction and targetVout
    const sigma = new Sigma(tx, 0, 0);

    // Sign the message
    const { sigmaScript, address, signature, signedTx } =
      sigma.sign(privateKey);

    console.log({ address, signature, signedTx });
    console.log({ sigmaScript: sigmaScript.to_asm_string() });

    // Verify the signature
    const isValid = sigma.verify();

    console.log("Signature is valid:", isValid);
    assert.strictEqual(isValid, true);
  });

  it("signed tx is verified", () => {
    // Build a simple transaction with the output script
    const tx = new Transaction(1, 0);
    const txOut = new TxOut(BigInt(0), script);
    tx.add_output(txOut);

    // Create a new Sigma instance with the transaction and targetVout
    const sigma = new Sigma(tx, 0, 0);

    // Sign the message
    const { signedTx } = sigma.sign(privateKey);

    const sigma2 = new Sigma(signedTx);
    const isValid2 = sigma2.verify();
    assert.strictEqual(isValid2, true);
  });
});
