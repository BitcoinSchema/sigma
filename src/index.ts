import {
	BSM,
	Hash,
	type PrivateKey,
	Script,
	Signature,
	Transaction,
	type TransactionOutput,
	BigNumber,
} from "@bsv/sdk";
import { Utils } from "@bsv/sdk";
const { magicHash } = BSM;
const {
	toHex,
  toArray
} = Utils

export type AuthToken = {
	type: "header" | "query";
	value: string;
	key: string;
};

export type RemoteSigningResponse = {
	address: string;
	sig: string;
	message: string;
	ts: number;
  recovery: number;
};

export const sigmaHex = "5349474d41";
export enum Algorithm {
	BSM = "BSM",
}

export type Sig = {
	address: string;
	signature: string;
	algorithm: Algorithm;
	vin: number;
	targetVout: number;
};

export interface SignResponse extends Sig {
	sigmaScript: Script;
	signedTx: Transaction;
}

export class Sigma {
	private _inputHash: number[] | null = null;
	private _dataHash: number[] | null = null;
	private _transaction: Transaction;
	private _sigmaInstance: number;
	private _refVin: number;
	private _targetVout: number;
	private _sig: Sig | null;

	constructor(
		transaction: Transaction,
		targetVout = 0,
		sigmaInstance = 0,
		refVin = 0,
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

	getMessageHash(): number[] {
		if (!this._inputHash || !this._dataHash) {
			throw new Error("Input hash and data hash must be set");
		}

		const inputBytes = this._inputHash;
		const dataBytes = this._dataHash;
		const combinedHashes = new Uint8Array(inputBytes.length + dataBytes.length);
		combinedHashes.set(inputBytes, 0);
		combinedHashes.set(dataBytes, inputBytes.length);
		// console.log("combinedHashes", Buffer.from(combinedHashes).toString('hex'))
		return Hash.sha256(Array.from(combinedHashes));
	}

	get transaction(): Transaction {
		return this._transaction;
	}

	_sign(signature: Signature, address: string, recovery: number) {
		const vin = this._refVin === -1 ? this._targetVout : this._refVin;
    if (recovery === undefined) {
      throw new Error("Failed recovery missing")
    }
		const signedAsm = `${sigmaHex} ${Buffer.from(
			Algorithm.BSM,
			"utf-8",
		).toString("hex")} ${Buffer.from(address, "utf-8").toString(
			"hex",
		)} ${signature.toCompact(recovery, true, "hex")} ${Buffer.from(
			vin.toString(),
			"utf-8",
		).toString("hex")}`;

		const sigmaScript = Script.fromASM(signedAsm);

		this._sig = {
			algorithm: Algorithm.BSM,
			address: address,
			signature: signature.toCompact(recovery, true, "base64") as string,
			vin,
			targetVout: this._targetVout,
		};

		let existingAsm = this.targetTxOut?.lockingScript.toASM();
		const containsOpReturn = existingAsm?.split(" ").includes("OP_RETURN");
		const separator = containsOpReturn ? "7c" : "OP_RETURN";

		let newScriptAsm = "";

		const existingSig = this.sig;

		// sigmaIndex is 0 based while count is 1 based
		if (existingSig && this._sigmaInstance === this.getSigInstanceCount()) {
			// Replace the existing signature
			const scriptChunks = existingAsm?.split(" ") || [];
			const sigIndex = this.getSigInstancePosition();

			const newSignedAsmChunks = signedAsm.split(" ");
			if (sigIndex !== -1) {
				existingAsm = scriptChunks
					.splice(sigIndex, 5, ...newSignedAsmChunks)
					.join("");
			}
		}
		// Append the new signature
		newScriptAsm = `${existingAsm} ${separator} ${signedAsm}`;

		const newScript = Script.fromASM(newScriptAsm);
		const signedTx = new Transaction(
			this._transaction.version,
			this._transaction.inputs.map(i => ({ ...i })),
			this._transaction.outputs.map(o => ({ ...o }))
		);
		const signedTxOut = {
			satoshis: this.targetTxOut?.satoshis,
			lockingScript: newScript,
		} as TransactionOutput;
		signedTx.outputs[this._targetVout] = signedTxOut;

		// update the object state
		this._transaction = signedTx;

		return {
			sigmaScript,
			signedTx,
			...this._sig,
		};
	}
	// Sign with Sigma protocol
	// privateKey: a @bsv/ts-sdk PrivateKey
	// inputs: either an array of TxIn from @bsv/ts-sdk or an array o string txids
	//    must be in the same order they are added to the transaction
	//    adding input txids to the signature scheme eliminates replay attacks
	// dataHash: a sha256 hash of the data to be signed
	//     it should include all the data in the output script prior to the "SIGMA" protocol instance
	//     excluding the "|" protocol separator and "SIGMA" prefix itself
	sign(privateKey: PrivateKey): SignResponse {
		const message = this.getMessageHash();
		const signature = BSM.sign(message, privateKey, 'raw') as Signature;
		const address = privateKey.toAddress();

    const h = new BigNumber(magicHash(message))
    const recovery = signature.CalculateRecoveryFactor(privateKey.toPublicKey(), h)
		return this._sign(signature, address, recovery);
	}
	async remoteSign(
		keyHost: string,
		authToken?: AuthToken,
	): Promise<SignResponse> {
		const headers = authToken
			? {
				[authToken.key]: authToken.value,
			}
			: {};

		const url = `${keyHost}/sign${authToken?.type === "query"
				? `?${authToken?.key}=${authToken?.value}`
				: ""
			}`;

		const requestBody = {
			message: toHex(this.getMessageHash()),
			encoding: "hex",
		};

		try {
			const response = await fetch(url, {
				method: "POST",
				headers: {
					...headers,
					"Content-Type": "application/json",
					Accept: "application/json",
				},
				body: JSON.stringify(requestBody),
			});

			if (!response.ok) {
				const errorResponse = await response.text();
				console.error("Response Error:", errorResponse);
				throw new Error(`HTTP Error: ${response.status}`);
			}

			const responseData = await response.json() as RemoteSigningResponse
			const { address, message, sig, recovery } = responseData;
			const signature = Signature.fromCompact(sig, "base64");

			return this._sign(signature, address, recovery);
		} catch (error) {
			console.error("Fetch Error:", error);
			throw error;
		}
	}

	verify = () => {
		if (!this.sig) {
			throw new Error("No signature data provided");
		}
		const msgHash = this.getMessageHash()
		if (!msgHash) {
			throw new Error("No tx data provided");
		}

		const signature = Signature.fromCompact(this.sig.signature, "base64");
    const recovery = deduceRecovery(signature, msgHash, this.sig.address)
		return recovery !== -1
	};

	getInputHash = (): number[] => {
		// if vin is -1, we're signing the corresponding input
		// so we use this._targetVout as the vin
		// this allows for better compatibility with partially signed transactions
		// where the anchor input index is not known
		const vin = this._refVin === -1 ? this._targetVout : this._refVin;
		return this._getInputHashByVin(vin);
	};

	private _getInputHashByVin = (vin: number): number[] => {
		const txIn = this._transaction.inputs[vin];
		if (txIn?.sourceTXID) {
			const outpointBytes = Buffer.alloc(36)
			const txidBuf = Buffer.from(txIn.sourceTXID, 'hex')
			outpointBytes.set(txidBuf, 0)
			outpointBytes.writeUInt32LE(txIn.sourceOutputIndex, 32)
			return Hash.sha256(Array.from(outpointBytes));
		}
		// using dummy hash
		return Hash.sha256(Array.from(new Uint8Array(32)));
	};

	// gets the Hash.sha256 for a given sigma instance within an output script
	// an example of 2 instances would be a user signature followed by a platform signature
	getDataHash = (): number[] => {
		if (!this._transaction) {
			throw new Error("No transaction provided");
		}
		const outputScript =
			this._transaction?.outputs[this._targetVout].lockingScript;

		const scriptChunks = outputScript?.toASM().split(" ") || [];

		// loop over the script chunks and set the endIndex when the nTh instance is found
		let occurances = 0;
		for (let i = 0; i < scriptChunks.length; i++) {
			if (scriptChunks[i].toUpperCase() === sigmaHex.toUpperCase()) {
				if (occurances === this._sigmaInstance) {
					// the -1 is to account for either the OP_RETURN
					// or "|" separator which is not signed
					const dataChunks = scriptChunks.slice(0, i - 1);
					const dataScript = Script.fromASM(dataChunks.join(" "));
					return Hash.sha256(dataScript.toBinary());
				}
				occurances++;
			}
		}

		// If no endIndex found, return the hash for the entire script
		const dataScript = Script.fromASM(scriptChunks.join(" "));
		return Hash.sha256(dataScript.toBinary());
	};

	get targetTxOut(): TransactionOutput | null {
		return this._transaction.outputs[this._targetVout] || null;
	}

	// get the signature from the selected sigma instance
	get sig(): Sig | null {
		const output = this._transaction.outputs[this._targetVout];
		const outputScript = output?.lockingScript;

		const scriptChunks = outputScript?.toASM().split(" ") || [];
		const instances: Sig[] = [];

		for (let i = 0; i < scriptChunks.length; i++) {
			if (scriptChunks[i].toUpperCase() === sigmaHex.toUpperCase()) {
				const sig = {
					algorithm: Buffer.from(scriptChunks[i + 1], "hex").toString("utf-8"),
					address: Buffer.from(scriptChunks[i + 2], "hex").toString("utf-8"),
					signature: Buffer.from(scriptChunks[i + 3], "hex").toString("base64"),
					vin: Number.parseInt(
						Buffer.from(scriptChunks[i + 4], "hex").toString("utf-8"),
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
		const existingAsm = this.targetTxOut?.lockingScript.toASM();
		const scriptChunks: string[] = existingAsm?.split(" ") || [];
		return scriptChunks.filter(
			(chunk) => chunk.toUpperCase() === sigmaHex.toUpperCase(),
		).length;
	}

	getSigInstancePosition(): number {
		const existingAsm = this.targetTxOut?.lockingScript.toASM();
		const scriptChunks: string[] = existingAsm?.split(" ") || [];
		return scriptChunks.findIndex(
			(chunk) => chunk.toUpperCase() === sigmaHex.toUpperCase(),
		);
	}
}


// Deduce the recovery factor for a given signature, returns -1 if recovery is not possible
const deduceRecovery = (signature: Signature, message: number[], address: string): number => {
  for (let recovery = 0; recovery < 4; recovery++) {
    try {
      const publicKey = signature.RecoverPublicKey(recovery, new BigNumber(magicHash(message)))
      const sigFitsPubkey = BSM.verify(message, signature, publicKey);
      if (sigFitsPubkey && publicKey.toAddress() === address) {
        return recovery
      }
    } catch (e) {
      // try next recovery
    }
  }
  return -1
}