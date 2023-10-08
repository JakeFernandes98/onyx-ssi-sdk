import axios from "axios";
import pako from "pako";
declare const Buffer: { from: (arg0: string, arg1: string) => any; }

interface RevocationListInterface {
    bitArray: BigUint64Array;
    getCredentialStatus: (index: number) => boolean;
    revokeCredential: (index: number) => void;
}

class RevocationList implements RevocationListInterface {
    static SIZE = 2000;
    static SIZE_PER_INDEX = 64;
    bitArray: BigUint64Array;

    constructor() {
        this.bitArray = new BigUint64Array(RevocationList.SIZE);
    }

    getBitArrayValues(index: number) {
        const arrayIndex =
      RevocationList.SIZE -
      1 -
      Math.floor(index / RevocationList.SIZE_PER_INDEX);
        const arrayValue = this.bitArray[arrayIndex];
        const bitIndex = index % RevocationList.SIZE_PER_INDEX;
        const mask = BigInt(1) << BigInt(bitIndex);

        return { arrayValue, mask, arrayIndex };
    }

    getCredentialStatus(index: number): boolean {
        const bitArrayValues = this.getBitArrayValues(index);

        const isRevoked =
      (bitArrayValues.arrayValue & bitArrayValues.mask) == bitArrayValues.mask;
        return isRevoked;
    }

    revokeCredential(index: number) {
        if (index > RevocationList.SIZE * RevocationList.SIZE_PER_INDEX) {
            throw new Error("[Revocation error] - index out of range");
        } else if (index < 0) {
            throw new Error("[Revocation error] - index out of range");
        }

        const bitArrayValues = this.getBitArrayValues(index);

        const newArrayValue = bitArrayValues.arrayValue | bitArrayValues.mask;

        this.bitArray[bitArrayValues.arrayIndex] = newArrayValue;
    }

    static async parse(input: string): Promise<RevocationList> {
        const decodedList = new RevocationList();

        // Base64 Decode
        const original_str = Buffer.from(input, "base64");

        // Unzip
        const originalText = pako.ungzip(original_str);

        decodedList.bitArray = new BigUint64Array(originalText.buffer);
        return decodedList;
    }

    // 1. Encode into base64
    static async stringify(input: RevocationList): Promise<string> {
    // Compress
        const new_str = pako.gzip(input.bitArray.buffer);

        // Base64 Encode
        const b64encoded_string = btoa(
            String.fromCharCode.apply(null, Array.from(new_str))
        );
        return b64encoded_string;
    }
}

export default RevocationList;
/**
 * The function `getRevocationStatus` retrieves the revocation status of a credential based on its ID
 * and a phone number.
 * @param {number} credId - The `credId` parameter is a number that represents the ID of a credential.
 * It is used to identify a specific credential in the revocation list.
 * @param {string} num - The `num` parameter is a string that represents a unique identifier for a
 * specific entity or object. It is used in the URL to fetch the revocation status from the API
 * endpoint.
 * @returns a Promise that resolves to the result of the revocation status of a credential.
 */

export const getRevocationStatus = async (credId: number, credListURL: string) => {
    const config = {
        method: "get",
        maxBodyLength: Infinity,
        url: `${credListURL}/list.json`,
        headers: {},
    };

    const result = axios
        .request(config)
        .then(async (response: { data: any }) => {
            const credentialList = response.data;
            const list: RevocationList = await RevocationList.parse(
                credentialList.credentialSubject.encodedList
            );
            const result = list.getCredentialStatus(credId);
            return result;

        })
        .catch((error: any) => {
            console.log(error);
        });

    return result;
};
