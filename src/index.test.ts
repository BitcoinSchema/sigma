import * as assert from "assert";
import { PrivateKey, Script, Transaction, TxIn, TxOut } from "bsv-wasm";
import { Sigma } from "./";

describe("Sigma Protocol", () => {
  // Test data
  const privateKey = PrivateKey.from_wif(
    "KzmFJcMXHufPNHixgHNwXBt3mHpErEUG6WFbmuQdy525DezYAi82"
  );

  const outputScriptAsm = `OP_0 OP_RETURN ${Buffer.from(
    "pushdata1",
    "utf-8"
  ).toString("hex")} ${Buffer.from("pushdata2", "utf-8").toString("hex")}`;

  const script = Script.from_asm_string(outputScriptAsm);
  // Build a simple transaction with the output script
  const tx = new Transaction(1, 0);
  const txOut = new TxOut(BigInt(0), script);
  tx.add_output(txOut);

  it("signs and verifies a message correctly", () => {
    // Create a new Sigma instance with the transaction and targetVout
    const sigma = new Sigma(tx, 0, 0);
    console.log({ messageHash: sigma.messageHash.to_hex() });
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
    // Create a new Sigma instance with the transaction and targetVout
    const sigma = new Sigma(tx, 0, 0);
    console.log({ messageHash: sigma.messageHash.to_hex() });

    // Sign the message
    const { signedTx } = sigma.sign(privateKey);

    const sigma2 = new Sigma(signedTx);
    const isValid2 = sigma2.verify();
    assert.strictEqual(isValid2, true);
  });

  it("replace a dummy signature with a real one", () => {
    // This is useful for calculating accurate fees considering the size of the
    // signature

    // Sign before adding inputs to create a dummy signature
    const sigma = new Sigma(tx, 0, 0);

    // Get the hashes before adding inputs
    const inputHash = sigma.getInputHash();
    const dataHash = sigma.getDataHash();

    // add some inputs
    const txIn = new TxIn(
      Buffer.from(
        "810755d937913d4228e1a4d192046d96c0642e2678d6a90e1cb794b0c2aeb78b",
        "hex"
      ),
      0,
      Script.from_asm_string(
        "OP_DUP OP_HASH160 5a009731beae590247297ecee0b1b54aa4b96c5d OP_EQUALVERIFY OP_CHECKSIG"
      )
    );
    tx.add_input(txIn);
    // input hash should change after adding inputs
    assert.notEqual(sigma.getInputHash(), inputHash);

    // sign again now that inputs have been added
    sigma.sign(privateKey);

    // data hash should change after replacing dummy signature
    assert.notEqual(sigma.getDataHash(), dataHash);

    assert.strictEqual(sigma.verify(), true);
  });

  it("specity an input to sign", () => {
    // This is useful for calculating accurate fees considering the size of the
    // signature

    // add some inputs
    const txIn = new TxIn(
      Buffer.from(
        "810755d937913d4228e1a4d192046d96c0642e2678d6a90e1cb794b0c2aeb78b",
        "hex"
      ),
      0,
      Script.from_asm_string(
        "OP_DUP OP_HASH160 5a009731beae590247297ecee0b1b54aa4b96c5d OP_EQUALVERIFY OP_CHECKSIG"
      )
    );
    const txIn2 = new TxIn(
      Buffer.from(
        "810755d937913d4228e1a4d192046d96c0642e2678d6a90e1cb794b0c2aeb78c",
        "hex"
      ),
      0,
      Script.from_asm_string(
        "OP_DUP OP_HASH160 5a009731beae590247297ecee0b1b54aa4b96c5c OP_EQUALVERIFY OP_CHECKSIG"
      )
    );
    tx.add_input(txIn);
    tx.add_input(txIn2);

    const sigma = new Sigma(tx, 0, 0, 1);

    // sign again now that inputs have been added
    sigma.sign(privateKey);

    assert.strictEqual(sigma.verify(), true);
  });

  it("create a user and platform signature on the same output", () => {
    // This is useful for calculating accurate fees
    // considering the size of the signature

    // Sign before adding inputs to create a dummy signature
    const sigma = new Sigma(tx, 0, 0);

    // sign now that inputs have been added
    const { signedTx } = sigma.sign(privateKey);

    assert.strictEqual(sigma.verify(), true);

    // Sign before adding inputs to create a dummy signature
    const sigma2 = new Sigma(signedTx, 0, 1);

    // sign now that inputs have been added
    sigma2.sign(privateKey);

    assert.strictEqual(sigma2.verify(), true);
  });
});
