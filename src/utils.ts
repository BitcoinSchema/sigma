import { Transaction, TxIn } from "bsv-wasm";

export const txInsFromTx = (tx: Transaction) => {
  const numInputs = tx.get_ninputs();
  const txIns: TxIn[] = [];
  for (let i = 0; i < numInputs; i++) {
    const txIn = tx.get_input(i);
    if (txIn) {
      txIns.push(txIn);
    }
  }
  if (txIns.length !== numInputs) {
    throw new Error("Failed to get all txIns from tx");
  }
  return txIns;
};

export const nthIndex = (str: string, subString, index) => {
  return string.split(subString, index).join(subString).length;
};
