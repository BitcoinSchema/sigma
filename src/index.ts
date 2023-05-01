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
  private _inputHash: Hash | null = null;
  private _dataHash: Hash | null = null;
  private _transaction: Transaction;
  private _sigmaInstance: number;
  private _targetVout: number;
  private _sig: Sig | null;

  constructor(
    transaction: Transaction,
    targetVout: number = 0,
    sigmaInstance: number = 0
  ) {
    this._transaction = transaction;
    this._targetVout = targetVout;
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

    return {
      sigmaScript,
      signedTx,
      ...this._sig,
    };
  }

  // sign(privateKey: PrivateKey): SignResponse {
  //   const message = this.messageHash;

  //   //let signature = P2PKHAddress.from_pubkey(PublicKey.from_private_key(privateKey)).
  //   let signature = BSM.sign_message(privateKey, message.to_bytes());

  //   const address = P2PKHAddress.from_pubkey(
  //     privateKey.to_public_key()
  //   ).to_string();

  //   const signedAsm = `${sigmaHex} ${Buffer.from(
  //     Algorithm.BSM,
  //     "utf-8"
  //   ).toString("hex")} ${Buffer.from(address, "utf-8").toString(
  //     "hex"
  //   )} ${signature.to_compact_hex()}`;

  //   const sigmaScript = Script.from_asm_string(signedAsm);

  //   this._sig = {
  //     algorithm: Algorithm.BSM,
  //     address: address,
  //     signature: Buffer.from(signature.to_compact_bytes()).toString("base64"),
  //   };

  //   // Build a signed version of this tx
  //   const existingAsm = this.targetTxOut?.get_script_pub_key().to_asm_string();
  //   const containsOpReturn = existingAsm?.split(" ").includes("OP_RETURN");
  //   // OP_SWAP in utf8 is the "|" protocol separator
  //   const separator = containsOpReturn ? "OP_SWAP" : "OP_RETURN";
  //   const newScript = Script.from_asm_string(
  //     `${existingAsm} ${separator} ${signedAsm}`
  //   );
  //   // Duplicate the tx
  //   const signedTx = Transaction.from_bytes(this._transaction.to_bytes());
  //   // update the script of the target vout
  //   const signedTxOut = new TxOut(this.targetTxOut!.get_satoshis(), newScript);
  //   signedTx.set_output(this._targetVout, signedTxOut);

  //   return {
  //     sigmaScript,
  //     signedTx,
  //     ...this._sig,
  //   };
  // }

  verify = () => {
    if (!this.sig || !this.messageHash) {
      throw new Error("No signature or tx data provided");
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

  getInputHash = () => {
    const txIns = txInsFromTx(this._transaction);
    return this._getInputHashByTxIns(txIns);
  };

  private _getInputHashByIds = (txInputIds: string[]): Hash => {
    const inputData = txInputIds.reduce((acc, txid) => {
      const txBuff = Buffer.from(txid, "hex");
      const newAcc = new Uint8Array(acc.length + txBuff.length);
      newAcc.set(acc);
      newAcc.set(txBuff, acc.length);
      return newAcc;
    }, new Uint8Array(0));

    return Hash.sha_256(inputData);
  };

  private _getInputHashByTxIns = (txIns: TxIn[]): Hash => {
    const txInputIds = txIns.map((txi) => txi.get_prev_tx_id_hex());
    return this._getInputHashByIds(txInputIds);
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
