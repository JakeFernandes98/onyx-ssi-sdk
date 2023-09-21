import * as crypto from 'crypto';
import { JwtCredentialPayload, VerifiableCredential, W3CCredential } from 'did-jwt-vc';
import * as jose from 'jose';
import { forEach } from 'lodash';

export enum DisclosureArray {
    SALT=0, NAME=1, VALUE=2
}

export const SALT_BYTE_SIZE = 128 / 8; // 128-bit salts

export interface sdJwtCredentialPayload extends Object, JwtCredentialPayload {
    _sd?: string[],
    _sd_alg?: string
}


// create disclosures for selectively-disclosable claims, and adds the sd digests into the SD-JWT (target)
export const createDisclosures = (hashAlg: string, claimValues: any, target: JwtCredentialPayload) => {
    let _disclosures: string[] = [];
    let sdDigests: string[] = [];
    const names = Object.keys(claimValues);
    const values: string[] = Object.values(claimValues);
    const salts: Buffer[] = names.map(v => crypto.randomBytes(SALT_BYTE_SIZE));
    for (let i = 0; i < names.length; i++) {
        if (typeof values[i] === 'object') {
            // create _sd recursively for nested objects TODO
            throw new Error("Not yet implemented");
        } else {
            // encode the salt using base64-url, as recommended by the spec
            const disclosureArray = [jose.base64url.encode(salts[i]), names[i], values[i]];
            const disclosure = encodeDisclosure(disclosureArray);
            _disclosures.push(disclosure);
            const disclosureDigest = hashDisclosure(hashAlg, disclosure);
            sdDigests.push(disclosureDigest);
        }
    }
    // add _sd property

    removeKeysFromObject(target.vc.credentialSubject, names)

    Object.defineProperty(target.vc.credentialSubject, "_sd", {value: sdDigests.sort(), enumerable: true}); // sort the sd values as recommended by the spec

    return { target, _disclosures };
}

// export const encodeAndHashEnclosure = (hashAlg: string, disclosureArray: string[]): string => {
//     const disclosure = encodeDisclosure(disclosureArray);
//     return hashDisclosure(hashAlg, disclosure);
// }

// export const checkDisclosure = (alg: string, sds: string[], disclosure: string): string => {
//     let prsd = parseDisclosure(disclosure)
//     let hashedDisclosure = encodeAndHashEnclosure(alg, prsd)
//     for (let i = 0; i < sds.length; i++) {
//         if (hashedDisclosure == sds[i]){
//             return prsd[2]
//         } 
//     }
//     return ""
// }

function removeKeysFromObject(obj: Object, keysToRemove: string[]): Object {
    keysToRemove.forEach(key => {
        delete obj[key as keyof Object];
    });
    return obj;
}

export const encodeDisclosure = (disclosureArray: string[]): string => {
    return jose.base64url.encode(JSON.stringify(disclosureArray))
}

// return the hash algorithm for the node crypto module api, lowercase, no hyphens
// e.g., 'SHA-256' --> 'sha256'
// TODO: this only works for the SHA2 family; the crypto module uses openssl names, a mapping
//       table should be used to support more algs (e.g., from the SHA3 family)
export const ianaToCryptoAlg = (hashAlg: string): string => {
    if (hashAlg == "ES256K") return 'sha256'
    if (hashAlg == "EdDSA") return 'sha512'
    return hashAlg.replace('-', '').toLowerCase(); 
}

export const hashDisclosure = (alg: string, disclosure: string): string => {
    let hash = crypto.createHash(ianaToCryptoAlg(alg))
    let disclosurehash = hash.update(disclosure)
    let disclosuredigest = disclosurehash.digest()
    return jose.base64url.encode(disclosuredigest);
}

export const parseDisclosure = (disclosure: string): string[] => {
    const input = jose.base64url.decode(disclosure);
    const inputBuffer = Buffer.from(input)
    const inputJSONString = inputBuffer.toString()
    const parsed: string[] = JSON.parse(inputJSONString);
    if (parsed.length != 3) {
        throw new Error("can't parse disclosure: " + disclosure);
    }
    return parsed;
}

export const discloseClaims = async (sdJwt: string, claims: string[]): Promise<string> => {
    // split SD-JWS into JWS and Disclosures
    const parts = sdJwt.split('~');
    if (parts.length <= 1) {
        throw new Error("No Disclosures found in SD-JWT");
    }
    const JWS = parts[0];
    let disclosures = parts.slice(1);
    disclosures = disclosures.filter(disclosure => claims.includes(parseDisclosure(disclosure)[DisclosureArray.NAME]));
    // if(disclosures.length == 0) return JWS
    // re-encode the updated SD-JWT w/ Disclosures
    const updatedSdJwt = JWS.concat("~" + disclosures.join("~"));
    return updatedSdJwt;
}

export interface SD_JWT {
    _sd: string[];
    _sd_alg: string;
}