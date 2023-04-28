import {
  BSM,
  Hash,
  P2PKHAddress,
  PrivateKey,
  Script,
  Signature,
  Transaction,
  TxIn,
  TxOut,
} from "bsv-wasm";
import { Buffer } from "buffer";
import { txInsFromTx } from "./utils";

export const sigmaHex = "5349474d41";
export enum Algorithm {
  "BSM" = "BSM",
}

export type Sig = {
  address: string;
  signature: string;
  algorithm: Algorithm;
};

export interface SignResponse extends Sig {
  sigmaScript: Script;
  signedTx: Transaction;
}

export class Sigma {
  private _inputHash: Hash;
  private _dataHash: Hash;
  private _transaction: Transaction;
  private _sigmaInstance: number;
  private _targetVout: number;
  private _sig: Sig | null = null;

  constructor(
    transaction: Transaction,
    targetVout: number = 0,
    sigmaInstance: number = 0
  ) {
    this._transaction = transaction;
    this._targetVout = targetVout;
    this._sigmaInstance = sigmaInstance;
    this._inputHash = this.getInputHash();
    this._dataHash = this.getDataHash();
    this._sig = null;
  }

  setTargetVout = (targetVout: number) => {
    this._targetVout = targetVout;
  };

  setSigmaInstance = (sigmaInstance: number) => {
    this._sigmaInstance = sigmaInstance;
  };

  // Sign with Sigma protocol
  // privateKey: a bsv-wasm PrivateKey
  // inputs: either an array of TxIn from bsv-wasm or an array o string txids
  //    must be in the same order they are added to the transaction
  //    adding input txids to the signature scheme eliminates replay attacks
  // dataHash: a sha256 hash of the data to be signed
  //     it should include all the data in the output script prior to the "SIGMA" protocol instance
  //     excluding the "|" protocol separator and "SIGMA" prefix itself
  sign(privateKey: PrivateKey): SignResponse {
    const combinedHashes = new Uint8Array([
      ...this._inputHash.to_bytes(),
      ...this._dataHash.to_bytes(),
    ]);
    const message = Hash.sha_256(combinedHashes);
    let signature = BSM.sign_message(privateKey, message.to_bytes());

    const address = P2PKHAddress.from_pubkey(
      privateKey.to_public_key()
    ).to_string();

    const signedAsm = `${sigmaHex} ${Buffer.from(
      Algorithm.BSM,
      "utf-8"
    ).toString("hex")} ${Buffer.from(address, "utf-8").toString(
      "hex"
    )} ${signature.to_compact_hex()}`;
    const sigmaScript = Script.from_asm_string(signedAsm);

    this._sig = {
      algorithm: Algorithm.BSM,
      address: address,
      signature: Buffer.from(signature.to_compact_bytes()).toString("base64"),
    };

    // lets build a signed version of this tx
    // const signedTxHex = this._transaction.to_hex();
    // const signedTx = Transaction.from_hex(signedTxHex);
    const existingAsm = this.targetTxOut?.get_script_pub_key().to_asm_string();
    const separator = existingAsm?.split(" ").includes("OP_RETURN")
      ? "OP_SWAP" // opcode equivelent of "|"
      : "OP_RETURN";
    const newScript = Script.from_asm_string(
      `${existingAsm} ${separator} ${signedAsm}`
    );
    // Duplicate the tx
    const signedTx = Transaction.from_bytes(this._transaction.to_bytes());
    // update the scrip[t of the target vout
    const signedTxOut = new TxOut(this.targetTxOut!.get_satoshis(), newScript);
    signedTx.set_output(this._targetVout, signedTxOut);

    return {
      sigmaScript,
      signedTx,
      ...this._sig,
    };
  }

  verify = () => {
    if (!this.sig) {
      throw new Error("No signature provided");
    }
    const p2pkhAddress = P2PKHAddress.from_string(this.sig.address);

    const combinedHashes = new Uint8Array([
      ...this._inputHash.to_bytes(),
      ...this._dataHash.to_bytes(),
    ]);
    const message = Hash.sha_256(combinedHashes);

    const signature = Signature.from_compact_bytes(
      Buffer.from(this.sig.signature, "base64")
    );
    console.log("Message:", message.to_hex()); // Add debug log
    console.log("Address:", p2pkhAddress.to_string()); // Add debug log
    console.log("Signature:", signature.to_compact_hex()); // Add debug log

    const isValid = BSM.verify_message(
      message.to_bytes(),
      signature,
      p2pkhAddress
    );

    return isValid;
  };

  getInputHash = (inputs: TxIn[] | string[] = [] as string[]) => {
    // concatenate the inputTxids into a single Uint8Array
    if ((inputs as any[]).every((input) => typeof input === "string")) {
      return this.getInputHashByIds(inputs as string[]);
    } else if (inputs.length === 0 && !!this._transaction) {
      const txIns = txInsFromTx(this._transaction);
      return this.getInputHashByTxIns(txIns);
    } else {
      return this.getInputHashByTxIns(inputs as TxIn[]);
    }
  };

  getInputHashByIds = (txInputIds: string[]): Hash => {
    const inputData = txInputIds.reduce((acc, txid) => {
      const txBuff = Buffer.from(txid, "hex");
      const newAcc = new Uint8Array(acc.length + txBuff.length);
      newAcc.set(acc);
      newAcc.set(txBuff, acc.length);
      return newAcc;
    }, new Uint8Array(0));

    return Hash.sha_256(inputData);
  };

  getInputHashByTxIns = (txIns: TxIn[]): Hash => {
    const txInputIds = txIns.map((txi) => txi.get_prev_tx_id_hex());
    return this.getInputHashByIds(txInputIds);
  };

  // gets the Hash.sha256 for a given sigma instance within an output script
  // an example of 2 instances would be a user signature followed by a platform signature
  getDataHash = (): Hash => {
    if (!this._transaction) {
      throw new Error("No transaction provided");
    }
    const outputScript = this._transaction
      ?.get_output(this._targetVout)
      ?.get_script_pub_key();

    const scriptChunks = outputScript?.to_asm_string().split(" ") || [];

    // loop over the script chunks and set the endIndex when the nTh instance is found
    let endIndex = 0;
    let occurances = 0;
    for (let i = 0; i < scriptChunks.length; i++) {
      if (scriptChunks[i].toUpperCase() === sigmaHex.toUpperCase()) {
        if (occurances === this._sigmaInstance) {
          endIndex = i;
          break;
        }
        occurances++;
      }
    }

    const dataChunks = scriptChunks.slice(0, endIndex);
    const dataScript = Script.from_asm_string(dataChunks.join(" "));

    return Hash.sha_256(dataScript.to_bytes());
  };

  get targetTxOut(): TxOut | null {
    return this._transaction?.get_output(this._targetVout) || null;
  }

  // get the signature from the selected sigma instance
  get sig(): Sig | null {
    if (this._sig) {
      return this._sig;
    }

    const output = this._transaction.get_output(this._targetVout);
    const outputScript = output?.get_script_pub_key();

    const scriptChunks = outputScript?.to_asm_string().split(" ") || [];
    const instances: Sig[] = [];

    for (let i = 0; i < scriptChunks.length; i++) {
      if (scriptChunks[i].toUpperCase() === sigmaHex.toUpperCase()) {
        const signature = Buffer.from(scriptChunks[i + 3], "hex").toString(
          "base64"
        );
        const address = Buffer.from(scriptChunks[i + 2], "hex").toString(
          "utf-8"
        );
        console.log("Generated signature:", signature); // Add debug log
        console.log("Generated address:", address); // Add debug log

        const sig = {
          algorithm: Buffer.from(scriptChunks[i + 1], "hex").toString("utf-8"),
          address,
          signature,
        } as Sig;
        console.log("Parsed sig from script:", sig); // Add debug log
        instances.push(sig);

        // fast forward to the next possible instance position
        // 3 firleds + 1 extra for the "|" separator
        i += 4;
      }
    }
    const sig = instances.length === 0 ? null : instances[this._sigmaInstance];
    this._sig = sig;
    return sig;
  }
}
