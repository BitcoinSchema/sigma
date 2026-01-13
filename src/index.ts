import {
	BSM,
	Hash,
	type PrivateKey,
	type PublicKey,
	Script,
	Signature,
	SignedMessage,
	Transaction,
	type TransactionOutput,
	BigNumber,
	Utils,
	OP,
} from "@bsv/sdk";

const { magicHash } = BSM;
const { toHex, toArray, toUTF8, toBase64 } = Utils;

/** SIGMA protocol identifier */
export const SIGMA_PREFIX = "SIGMA";
export const sigmaHex = "5349474d41";

/** Convert hex string to byte array */
const hexToBytes = (hex: string): number[] => {
	const bytes: number[] = [];
	for (let i = 0; i < hex.length; i += 2) {
		bytes.push(Number.parseInt(hex.substring(i, i + 2), 16));
	}
	return bytes;
};

/** Write a 32-bit unsigned integer in little-endian format */
const writeUint32LE = (value: number): number[] => {
	return [
		value & 0xff,
		(value >> 8) & 0xff,
		(value >> 16) & 0xff,
		(value >> 24) & 0xff,
	];
};

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

export enum Algorithm {
	BSM = "BSM",
	BRC77 = "BRC77",
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

/**
 * Parse SIGMA instances from a script using chunk-based parsing
 * Handles both standard format and OP_RETURN embedded format
 */
function parseSigmaInstances(script: Script, targetVout: number): Sig[] {
	const instances: Sig[] = [];
	const chunks = script.chunks;

	for (let i = 0; i < chunks.length; i++) {
		const chunk = chunks[i];

		// Check for standard format: SIGMA as a separate data chunk
		if (chunk.data && toUTF8(chunk.data) === SIGMA_PREFIX) {
			// Standard format: SIGMA | algorithm | address | signature | vin
			if (i + 4 < chunks.length) {
				const algoChunk = chunks[i + 1];
				const addrChunk = chunks[i + 2];
				const sigChunk = chunks[i + 3];
				const vinChunk = chunks[i + 4];

				if (algoChunk?.data && addrChunk?.data && sigChunk?.data && vinChunk?.data) {
					instances.push({
						algorithm: toUTF8(algoChunk.data) as Algorithm,
						address: toUTF8(addrChunk.data),
						signature: toBase64(sigChunk.data),
						vin: Number.parseInt(toUTF8(vinChunk.data), 10),
						targetVout,
					});
					i += 4; // Skip past the SIGMA fields
				}
			}
		}
		// Check for OP_RETURN embedded format
		else if (chunk.op === OP.OP_RETURN && chunk.data && chunk.data.length > 0) {
			// Parse the OP_RETURN data as an inner script
			try {
				const innerScript = Script.fromBinary(chunk.data);
				const innerChunks = innerScript.chunks;

				for (let j = 0; j < innerChunks.length; j++) {
					const innerChunk = innerChunks[j];

					if (innerChunk.data && toUTF8(innerChunk.data) === SIGMA_PREFIX) {
						// Found SIGMA in inner script
						if (j + 4 < innerChunks.length) {
							const algoChunk = innerChunks[j + 1];
							const addrChunk = innerChunks[j + 2];
							const sigChunk = innerChunks[j + 3];
							const vinChunk = innerChunks[j + 4];

							if (algoChunk?.data && addrChunk?.data && sigChunk?.data && vinChunk?.data) {
								instances.push({
									algorithm: toUTF8(algoChunk.data) as Algorithm,
									address: toUTF8(addrChunk.data),
									signature: toBase64(sigChunk.data),
									vin: Number.parseInt(toUTF8(vinChunk.data), 10),
									targetVout,
								});
								j += 4;
							}
						}
					}
				}
			} catch {
				// Failed to parse inner script, continue
			}
		}
	}

	return instances;
}

/**
 * Count SIGMA instances in a script using chunk-based parsing
 */
function countSigmaInstances(script: Script): number {
	return parseSigmaInstances(script, 0).length;
}

/**
 * Find the position of SIGMA in script chunks for data hash calculation
 * Returns the chunk index where SIGMA starts, or -1 if not found
 */
function findSigmaPosition(script: Script, instanceIndex: number): number {
	const chunks = script.chunks;
	let occurrences = 0;

	for (let i = 0; i < chunks.length; i++) {
		const chunk = chunks[i];

		// Check for standard format
		if (chunk.data && toUTF8(chunk.data) === SIGMA_PREFIX) {
			if (occurrences === instanceIndex) {
				return i;
			}
			occurrences++;
		}
		// Check for OP_RETURN embedded format
		else if (chunk.op === OP.OP_RETURN && chunk.data && chunk.data.length > 0) {
			try {
				const innerScript = Script.fromBinary(chunk.data);
				for (const innerChunk of innerScript.chunks) {
					if (innerChunk.data && toUTF8(innerChunk.data) === SIGMA_PREFIX) {
						if (occurrences === instanceIndex) {
							return i; // Return the OP_RETURN chunk index
						}
						occurrences++;
					}
				}
			} catch {
				// Continue
			}
		}
	}

	return -1;
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
		this.setHashes();
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
		return Hash.sha256(Array.from(combinedHashes));
	}

	get transaction(): Transaction {
		return this._transaction;
	}

	/**
	 * Apply signature to transaction and update state
	 * Common logic for both BSM and BRC-77 signing
	 */
	private _applySignature(signedAsm: string, sig: Sig): SignResponse {
		const sigmaScript = Script.fromASM(signedAsm);
		this._sig = sig;

		let existingAsm = this.targetTxOut?.lockingScript.toASM();
		const containsOpReturn = existingAsm?.split(" ").includes("OP_RETURN");
		const separator = containsOpReturn ? "7c" : "OP_RETURN";

		const existingSig = this.sig;
		if (existingSig && this._sigmaInstance === this.getSigInstanceCount()) {
			const scriptChunks = existingAsm?.split(" ") || [];
			const sigIndex = this.getSigInstancePosition();
			if (sigIndex !== -1) {
				scriptChunks.splice(sigIndex, 5, ...signedAsm.split(" "));
				existingAsm = scriptChunks.join(" ");
			}
		}

		const newScriptAsm = `${existingAsm} ${separator} ${signedAsm}`;
		const newScript = Script.fromASM(newScriptAsm);

		const signedTx = new Transaction(
			this._transaction.version,
			this._transaction.inputs.map((i) => ({ ...i })),
			this._transaction.outputs.map((o) => ({ ...o })),
		);
		signedTx.outputs[this._targetVout] = {
			satoshis: this.targetTxOut?.satoshis,
			lockingScript: newScript,
		} as TransactionOutput;

		this._transaction = signedTx;

		return { sigmaScript, signedTx, ...this._sig };
	}

	/**
	 * Sign with BSM (internal)
	 */
	_sign(signature: Signature, address: string, recovery: number): SignResponse {
		if (recovery === undefined) {
			throw new Error("Failed recovery missing");
		}

		const vin = this._refVin === -1 ? this._targetVout : this._refVin;
		const signedAsm = `${sigmaHex} ${toHex(toArray(Algorithm.BSM))} ${toHex(toArray(address))} ${signature.toCompact(recovery, true, "hex")} ${toHex(toArray(vin.toString()))}`;

		const sig: Sig = {
			algorithm: Algorithm.BSM,
			address,
			signature: signature.toCompact(recovery, true, "base64") as string,
			vin,
			targetVout: this._targetVout,
		};

		return this._applySignature(signedAsm, sig);
	}

	/**
	 * Sign with Sigma protocol
	 * @param privateKey - a @bsv/sdk PrivateKey
	 * @param algorithm - signing algorithm (default: BSM)
	 * @param verifier - for BRC77, optional public key of specific verifier (omit for anyone-can-verify)
	 */
	sign(privateKey: PrivateKey, algorithm: Algorithm = Algorithm.BSM, verifier?: PublicKey): SignResponse {
		const message = this.getMessageHash();

		if (algorithm === Algorithm.BRC77) {
			return this._signBRC77(message, privateKey, verifier);
		}

		const signature = BSM.sign(message, privateKey, "raw") as Signature;
		const address = privateKey.toAddress();
		const h = new BigNumber(magicHash(message));
		const recovery = signature.CalculateRecoveryFactor(privateKey.toPublicKey(), h);

		return this._sign(signature, address, recovery);
	}

	/**
	 * Sign with BRC-77 message signing protocol
	 */
	private _signBRC77(message: number[], privateKey: PrivateKey, verifier?: PublicKey): SignResponse {
		const vin = this._refVin === -1 ? this._targetVout : this._refVin;
		const address = privateKey.toAddress();
		const brc77Sig = SignedMessage.sign(message, privateKey, verifier);

		const signedAsm = `${sigmaHex} ${toHex(toArray(Algorithm.BRC77))} ${toHex(toArray(address))} ${toHex(brc77Sig)} ${toHex(toArray(vin.toString()))}`;

		const sig: Sig = {
			algorithm: Algorithm.BRC77,
			address,
			signature: toBase64(brc77Sig),
			vin,
			targetVout: this._targetVout,
		};

		return this._applySignature(signedAsm, sig);
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

		const url = `${keyHost}/sign${
			authToken?.type === "query"
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

			const responseData = (await response.json()) as RemoteSigningResponse;
			const { address, sig, recovery } = responseData;
			const signature = Signature.fromCompact(sig, "base64");

			return this._sign(signature, address, recovery);
		} catch (error) {
			console.error("Fetch Error:", error);
			throw error;
		}
	}

	/**
	 * Verify the signature
	 * @param recipientPrivateKey - for BRC77 private signatures, the recipient's private key
	 */
	verify = (recipientPrivateKey?: PrivateKey) => {
		if (!this.sig) {
			throw new Error("No signature data provided");
		}
		const msgHash = this.getMessageHash();
		if (!msgHash) {
			throw new Error("No tx data provided");
		}

		if (this.sig.algorithm === Algorithm.BRC77) {
			// BRC-77 verification
			const sigBytes = toArray(this.sig.signature, "base64");
			return SignedMessage.verify(msgHash, sigBytes, recipientPrivateKey);
		}

		// BSM verification
		const signature = Signature.fromCompact(this.sig.signature, "base64");
		const recovery = deduceRecovery(signature, msgHash, this.sig.address);
		return recovery !== -1;
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
			// Build outpoint: 32-byte txid + 4-byte output index (little endian)
			const txidBytes = hexToBytes(txIn.sourceTXID);
			const indexBytes = writeUint32LE(txIn.sourceOutputIndex);
			const outpointBytes = [...txidBytes, ...indexBytes];
			return Hash.sha256(outpointBytes);
		}
		// using dummy hash
		return Hash.sha256(new Array(32).fill(0));
	};

	/**
	 * Gets the Hash.sha256 for a given sigma instance within an output script
	 * An example of 2 instances would be a user signature followed by a platform signature
	 */
	getDataHash = (): number[] => {
		if (!this._transaction) {
			throw new Error("No transaction provided");
		}
		const outputScript =
			this._transaction?.outputs[this._targetVout].lockingScript;

		const chunks = outputScript.chunks;
		let occurrences = 0;

		// Find the SIGMA instance and calculate hash of data before it
		for (let i = 0; i < chunks.length; i++) {
			const chunk = chunks[i];

			// Check for standard format: SIGMA as a separate data chunk
			if (chunk.data && toUTF8(chunk.data) === SIGMA_PREFIX) {
				if (occurrences === this._sigmaInstance) {
					// Hash everything before the separator (pipe or OP_RETURN before SIGMA)
					// The -1 accounts for the separator
					const dataChunks = chunks.slice(0, i - 1);
					const dataScript = new Script();
					for (const c of dataChunks) {
						if (c.op !== undefined && c.data === undefined) {
							dataScript.writeOpCode(c.op);
						} else if (c.data) {
							dataScript.writeBin(c.data);
						}
					}
					return Hash.sha256(dataScript.toBinary());
				}
				occurrences++;
			}
			// Check for OP_RETURN embedded format
			else if (chunk.op === OP.OP_RETURN && chunk.data && chunk.data.length > 0) {
				try {
					const innerScript = Script.fromBinary(chunk.data);
					for (const innerChunk of innerScript.chunks) {
						if (innerChunk.data && toUTF8(innerChunk.data) === SIGMA_PREFIX) {
							if (occurrences === this._sigmaInstance) {
								// For OP_RETURN embedded format, hash everything before the OP_RETURN chunk
								const dataChunks = chunks.slice(0, i);
								const dataScript = new Script();
								for (const c of dataChunks) {
									if (c.op !== undefined && c.data === undefined) {
										dataScript.writeOpCode(c.op);
									} else if (c.data) {
										dataScript.writeBin(c.data);
									}
								}
								return Hash.sha256(dataScript.toBinary());
							}
							occurrences++;
						}
					}
				} catch {
					// Continue if inner script parsing fails
				}
			}
		}

		// If no SIGMA found, return the hash for the entire script
		return Hash.sha256(outputScript.toBinary());
	};

	get targetTxOut(): TransactionOutput | null {
		return this._transaction.outputs[this._targetVout] || null;
	}

	/**
	 * Get the signature from the selected sigma instance
	 * Uses chunk-based parsing to handle both standard and OP_RETURN embedded formats
	 */
	get sig(): Sig | null {
		const output = this._transaction.outputs[this._targetVout];
		if (!output?.lockingScript) {
			return this._sig;
		}

		const instances = parseSigmaInstances(output.lockingScript, this._targetVout);

		if (instances.length === 0) {
			return this._sig;
		}

		return instances[this._sigmaInstance] ?? null;
	}

	getSigInstanceCount(): number {
		const script = this.targetTxOut?.lockingScript;
		if (!script) return 0;
		return countSigmaInstances(script);
	}

	getSigInstancePosition(): number {
		const script = this.targetTxOut?.lockingScript;
		if (!script) return -1;
		return findSigmaPosition(script, this._sigmaInstance);
	}
}

/**
 * Deduce the recovery factor for a given signature
 * @returns Recovery factor (0-3) or -1 if recovery is not possible
 */
const deduceRecovery = (
	signature: Signature,
	message: number[],
	address: string,
): number => {
	for (let recovery = 0; recovery < 4; recovery++) {
		try {
			const publicKey = signature.RecoverPublicKey(
				recovery,
				new BigNumber(magicHash(message)),
			);
			const sigFitsPubkey = BSM.verify(message, signature, publicKey);
			if (sigFitsPubkey && publicKey.toAddress() === address) {
				return recovery;
			}
		} catch {
			// try next recovery
		}
	}
	return -1;
};
