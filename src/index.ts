import {
  BSM,
  Hash,
  P2PKHAddress,
  PrivateKey,
  Script,
  Signature,
  Transaction,
  TxOut,
} from "bsv-wasm";
import { Buffer } from "buffer";

export const sigmaHex = "5349474d41";
export enum Algorithm {
  "BSM" = "BSM",
}

export type Sig = {
  address: string;
  signature: string;
  algorithm: Algorithm;
  vin: number;
};

export interface SignResponse extends Sig {
  sigmaScript: Script;
  signedTx: Transaction;
}

export class Sigma {
  private _inputHash: Hash | null = null;
  private _dataHash: Hash | null = null;
  private _transaction: Transaction;
  private _sigmaInstance: number;
  private _refVin: number;
  private _targetVout: number;
  private _sig: Sig | null;

  constructor(
    transaction: Transaction,
    targetVout: number = 0,
    sigmaInstance: number = 0,
    refVin: number = 0
  ) {
    this._transaction = transaction;
    this._targetVout = targetVout;
    this._refVin = refVin;
    this._sigmaInstance = sigmaInstance;
    this._sig = this.sig;
    this.setHashes();
  }

  setHashes = () => {
    this._inputHash = this.getInputHash();
    this._dataHash = this.getDataHash();
  };

  setTargetVout = (targetVout: number) => {
    this._targetVout = targetVout;
  };

  setSigmaInstance = (sigmaInstance: number) => {
    this._sigmaInstance = sigmaInstance;
  };

  get messageHash(): Hash {
    if (!this._inputHash || !this._dataHash) {
      throw new Error("Input hash and data hash must be set");
    }

    const combinedHashes = new Uint8Array([
      ...this._inputHash.to_bytes(),
      ...this._dataHash.to_bytes(),
    ]);

    return Hash.sha_256(combinedHashes);
  }

  // Sign with Sigma protocol
  // privateKey: a bsv-wasm PrivateKey
  // inputs: either an array of TxIn from bsv-wasm or an array o string txids
  //    must be in the same order they are added to the transaction
  //    adding input txids to the signature scheme eliminates replay attacks
  // dataHash: a sha256 hash of the data to be signed
  //     it should include all the data in the output script prior to the "SIGMA" protocol instance
  //     excluding the "|" protocol separator and "SIGMA" prefix itself
  sign(privateKey: PrivateKey): SignResponse {
    const message = this.messageHash;
    const vin = this._refVin === -1 ? this._targetVout : this._refVin;

    let signature = BSM.sign_message(privateKey, message.to_bytes());

    const address = P2PKHAddress.from_pubkey(
      privateKey.to_public_key()
    ).to_string();

    const signedAsm = `${sigmaHex} ${Buffer.from(
      Algorithm.BSM,
      "utf-8"
    ).toString("hex")} ${Buffer.from(address, "utf-8").toString(
      "hex"
    )} ${signature.to_compact_hex()} ${Buffer.from(
      vin.toString(),
      "utf-8"
    ).toString("hex")}`;

    const sigmaScript = Script.from_asm_string(signedAsm);

    this._sig = {
      algorithm: Algorithm.BSM,
      address: address,
      signature: Buffer.from(signature.to_compact_bytes()).toString("base64"),
      vin,
    };

    const existingAsm = this.targetTxOut?.get_script_pub_key().to_asm_string();
    const containsOpReturn = existingAsm?.split(" ").includes("OP_RETURN");
    const separator = containsOpReturn ? "OP_SWAP" : "OP_RETURN";

    let newScriptAsm = "";

    const existingSig = this.sig;

    // sigmaIndex is 0 based while count is 1 based
    if (existingSig && this._sigmaInstance === this.getSigInstanceCount()) {
      // Replace the existing signature
      const scriptChunks = existingAsm?.split(" ") || [];
      const sigIndex = scriptChunks.indexOf(sigmaHex.toUpperCase());

      newScriptAsm = [
        ...scriptChunks.slice(0, sigIndex),
        signedAsm,
        ...scriptChunks.slice(sigIndex + 4),
      ].join(" ");
    } else {
      // Append the new signature
      newScriptAsm = `${existingAsm} ${separator} ${signedAsm}`;
    }

    const newScript = Script.from_asm_string(newScriptAsm);
    const signedTx = Transaction.from_bytes(this._transaction.to_bytes());
    const signedTxOut = new TxOut(this.targetTxOut!.get_satoshis(), newScript);
    signedTx.set_output(this._targetVout, signedTxOut);

    this._transaction = signedTx;

    return {
      sigmaScript,
      signedTx,
      ...this._sig,
    };
  }

  verify = () => {
    if (!this.sig) {
      // TODO - this is throwing when trying to verify a tx returned from previous signing
      throw new Error("No signature data provided");
    }
    if (!this.messageHash) {
      throw new Error("No tx data provided");
    }

    const p2pkhAddress = P2PKHAddress.from_string(this.sig.address);
    const signature = Signature.from_compact_bytes(
      Buffer.from(this.sig.signature, "base64")
    );

    return p2pkhAddress.verify_bitcoin_message(
      this.messageHash.to_bytes(),
      signature
    );
  };

  getInputHash = (): Hash => {
    // if vin is -1, we're signing the corresponding input
    // so we use this._targetVout as the vin
    // this allows for better compatibility with partially signed transactions
    // where the anchor input index is not known
    const vin = this._refVin === -1 ? this._targetVout : this._refVin;
    return this._getInputHashByVin(vin);
  };

  private _getInputHashByVin = (vin: number): Hash => {
    const txIn = this._transaction.get_input(vin);
    if (txIn) {
      return Hash.sha_256(txIn.get_outpoint_bytes());
    }
    // using dummy hash
    return Hash.sha_256(new Uint8Array(32));
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
    let endIndex: number | null = null;
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

    // the -1 is to account for either the OP_RETURN
    // or "|" separator which is not signed
    const dataChunks = scriptChunks.slice(
      0,
      endIndex === null ? scriptChunks.length : endIndex - 1
    );
    const dataScript = Script.from_asm_string(dataChunks.join(" "));
    return Hash.sha_256(dataScript.to_bytes());
  };

  get targetTxOut(): TxOut | null {
    return this._transaction?.get_output(this._targetVout) || null;
  }

  // get the signature from the selected sigma instance
  get sig(): Sig | null {
    const output = this._transaction.get_output(this._targetVout);
    const outputScript = output?.get_script_pub_key();

    const scriptChunks = outputScript?.to_asm_string().split(" ") || [];
    const instances: Sig[] = [];

    for (let i = 0; i < scriptChunks.length; i++) {
      if (scriptChunks[i].toUpperCase() === sigmaHex.toUpperCase()) {
        const sig = {
          algorithm: Buffer.from(scriptChunks[i + 1], "hex").toString("utf-8"),
          address: Buffer.from(scriptChunks[i + 2], "hex").toString("utf-8"),
          signature: Buffer.from(scriptChunks[i + 3], "hex").toString("base64"),
          vin: parseInt(
            Buffer.from(scriptChunks[i + 4], "hex").toString("utf-8")
          ),
        } as Sig;

        instances.push(sig);

        // fast forward to the next possible instance position
        // 3 fields + 1 extra for the "|" separator
        i += 4;
      }
    }
    return instances.length === 0 ? this._sig : instances[this._sigmaInstance];
  }

  getSigInstanceCount(): number {
    const existingAsm = this.targetTxOut?.get_script_pub_key().to_asm_string();
    const scriptChunks = existingAsm?.split(" ") || [];
    return scriptChunks.filter(
      (chunk) => chunk.toUpperCase() === sigmaHex.toUpperCase()
    ).length;
  }
}
