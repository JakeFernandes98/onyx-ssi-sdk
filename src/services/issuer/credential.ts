import { DEFAULT_CONTEXT, DID, DIDMethod, DIDWithKeys, JWTService, SCHEMA_VALIDATOR, VERIFIABLE_CREDENTIAL } from "../common";
import { CreateCredentialOptions, CredentialPayload, VerifiableCredential } from 'did-jwt-vc'
import { JWTPayload } from "did-jwt";
import axios from "axios";
import RevocationList from "../common/revocation/revocation";

/**
 * Creates a {@link CredentialPayload} from supplied Issuer DID, subject DID,
 * subjectData, and CredentialType
 * 
 * The Verifiable Credential object created follows the 
 * [W3C Verifiable Credential standards](https://www.w3.org/TR/vc-data-model/#basic-concepts)
 * The Verifiable Credential created has not been signed yet.
 * 
 * Additional properties can be supplied to this function. These properties should be defined
 * in the W3C spec.
 * 
 * @param issuerDID DID of the Issuer
 * @param subjectDID DID of the Subject of the VC
 * @param credentialSubject subject data to be included in the VC
 * @param credentialType type of the VC
 * @param additionalProperties other W3C spec compliant properties of a VC
 * @returns `CredentialPayload` representing the W3C Verifiable Credential object
 */
export function createCredential(
    issuerDID: DID,
    subjectDID: DID,
    credentialSubject: CredentialSubject,
    credentialType: string[],
    additionalProperties?: Partial<CredentialPayload>
) : CredentialPayload {
    let credential: Partial<CredentialPayload> = {}
    const currentTimeInSeconds = Math.floor(new Date().getTime() / 1000);
    const validFrom = new Date();
    validFrom.setTime(currentTimeInSeconds * 1000);

    credential["@context"] = [DEFAULT_CONTEXT]
    credential.credentialSubject = {id: subjectDID, ...credentialSubject}
    credential.issuer = {id : issuerDID}
    credential.type = [VERIFIABLE_CREDENTIAL, ...credentialType]
    credential.issuanceDate = validFrom.toISOString()

    credential = Object.assign(credential, additionalProperties)

    return credential as CredentialPayload

}

/**
 * Creates a {@link CredentialPayload} from supplied Issuer DID, subject DID,
 * subjectData, and CredentialType, and a VC JSON schema.
 * This method automatically adds the `credentialSchema` property of the VC using the supplied
 * schema location. The type of the credentialSchema is defined by `SCHEMA_VALIDATOR` which 
 * should be configurable.
 * 
 * The Verifiable Credential object created follows the 
 * [W3C Verifiable Credential standards](https://www.w3.org/TR/vc-data-model/#basic-concepts)
 * The Verifiable Credential created has not been signed yet.
 * 
 * Additional properties can be supplied to this function. These properties should be defined
 * in the W3C spec.
 * 
 * @param schema location of the JSON schema for this credential
 * @param issuerDID DID of the Issuer
 * @param subjectDID DID of the Subject of the VC
 * @param credentialSubject subject data to be included in the VC
 * @param credentialType type of the VC
 * @param additionalProperties other W3C spec compliant properties of a VC
 * @returns `CredentialPayload` representing the W3C Verifiable Credential object with 
 * the `credentialSchema` populated
 */
export async function createCredentialFromSchema(
    schema: string,
    issuerDID: DID,
    subjectDID: DID,
    credentialSubject: CredentialSubject,
    credentialType: string,
    additionalProperties?: Partial<CredentialPayload>
) : Promise<CredentialPayload> {
    let credential: Partial<CredentialPayload> = {}
    const currentTimeInSeconds = Math.floor(new Date().getTime() / 1000);
    const validFrom = new Date();
    validFrom.setTime(currentTimeInSeconds * 1000);

    credential["@context"] = [DEFAULT_CONTEXT]
    credential.credentialSubject = {id: subjectDID, ...credentialSubject}
    credential.issuer = {id : issuerDID}
    credential.type = [VERIFIABLE_CREDENTIAL, credentialType]
    credential.issuanceDate = validFrom.toISOString()
    credential.credentialSchema = {
        id: schema,
        type: SCHEMA_VALIDATOR
    }

    credential = Object.assign(credential, additionalProperties)

    return credential as CredentialPayload

}

/**
 * Creates a Verifiable Credential JWT from {@link DIDWithKeys} and
 * required properties of the Verifiable Credential
 * 
 * This method first creates the Credential object from the DID of the Issuer, the DID of the subject,
 * the credentialType and the credentialSubject. This object becomes the payload that is transformed into the 
 * [JWT encoding](https://www.w3.org/TR/vc-data-model/#jwt-encoding)
 * described in the [W3C VC spec](https://www.w3.org/TR/vc-data-model)
 *
 * The `DIDWithKeys` is used to sign the JWT that encodes the Verifiable Credential.
 * 
 * @param issuer 
 * @param subjectDID 
 * @param credentialSubject 
 * @param credentialType 
 * @param additionalProperties 
 * @param options 
 * @returns 
 */
export async function createAndSignCredentialJWT(
    issuer: DIDWithKeys,
    subjectDID: DID,
    credentialSubject: CredentialSubject,
    credentialType: string[],
    additionalProperties?: Partial<CredentialPayload>,
    options?: CreateCredentialOptions,
): Promise<string> {
    const payload = await createCredential(
        issuer.did, subjectDID, credentialSubject, credentialType, additionalProperties)
    const jwtService = new JWTService()
    return await jwtService.signVC(issuer, payload, options)

}

/**
 * Creates a Verifiable Credential SD-JWT from {@link DIDWithKeys} and
 * required properties of the Verifiable Credential
 *
 * The `DIDWithKeys` is used to sign the JWT that encodes the Verifiable Credential.
 * 
 * @param issuer 
 * @param subjectDID 
 * @param credentialSubject 
 * @param credentialType 
 * @param claimValues
 * @param additionalProperties 
 * @param options 
 * @returns 
 */
export async function createAndSignCredentialSDJWT(
    issuer: DIDWithKeys,
    subjectDID: DID,
    credentialSubject: CredentialSubject,
    credentialType: string[],
    claimValues: CredentialSubject,
    additionalProperties?: Partial<CredentialPayload>,
    options?: CreateCredentialOptions,
): Promise<string> {
    const payload = await createCredential(
        issuer.did, subjectDID, credentialSubject, credentialType, additionalProperties)

    const jwtService = new JWTService()
    let jwt = await jwtService.signVC(issuer, payload, options)
    let { jwtPayload, disclosures } = await jwtService.createSelectiveDisclosures(issuer, jwt, claimValues)
    return await jwtService.signSelectiveDisclosure(issuer, jwtPayload, disclosures)
}

/**
 * This method deactivates an Onyx Verifiable Credential
 * 
 * Onyx revocable credentials require the VC to have a DID registered on the DIDRegistry.
 * Revocation involves the Issuer deactivating this DID to revoke the Credential
 * 
 * @param vcDID the DID of the Verifiable Credential to be revoked
 * @param didMethod the DID method of the vcDID
 * @returns a `Promise` resolving to if the deactivation succeeded
 * A `DIDMethodFailureError` thrown if the DID method does not support deactivation
 */
export async function revokeCredential(vcDID: DIDWithKeys, didMethod: DIDMethod): Promise<boolean> {
    return await didMethod.deactivate(vcDID)
}

/**
 * The `revokeCredentialSL21` function revokes a Verifiable Credential by updating a status list and
 * creating a new credential with the updated revocation list.
 * 
 * @param {VerifiableCredential} vc - The `vc` parameter represents the Verifiable Credential that
 * needs to be revoked.
 * @param {DID} issuerDID - The `issuerDID` parameter is the decentralized identifier (DID) of the
 * entity that issued the verifiable credential. It uniquely identifies the issuer and is used to
 * verify the authenticity of the credential.
 * @param {DID} subjectDID - The `subjectDID` parameter in the `revokeCredentialSL21` function
 * represents the decentralized identifier (DID) of the subject for whom the credential is being
 * revoked. A DID is a unique identifier that is associated with a specific entity or individual on a
 * decentralized network. In this context,
 * @returns a boolean value. If the conditions inside the function are met and the necessary operations
 * are successfully executed, it will return `true`. Otherwise, it will return `false`.
 */
export function revokeCredentialSL21(
    vc: VerifiableCredential,
    issuerDID: DID,
    subjectDID: DID,
): boolean {
    if (typeof vc !== "string") {
        if (
            vc.credentialStatus !== undefined &&
      vc.credentialStatus?.type == "StatusList2021Entry"
        ) {
            const listUrl = vc.credentialStatus?.id.split("#")[0];
            const credId: number = parseInt(
                vc.credentialStatus?.id.split("#").slice(-1)[0]
            );

            const config = {
                method: "get",
                maxBodyLength: Infinity,
                url: `${listUrl}/list.json`,
                headers: {},
            };

            const _result = axios
                .request(config)
                .then(async (response: { data: any }) => {
                    const credentialList = response.data;

                    const list: RevocationList = await RevocationList.parse(
                        credentialList.credentialSubject.encodedList
                    );

                    list.revokeCredential(credId);

                    const credentialSubject: CredentialSubject = {
                        id: credentialList.credentialSubject.id,
                        type: credentialList.credentialSubject.type,
                        purpose: credentialList.credentialSubject.purpose,
                        encodedList: await RevocationList.stringify(list),
                    };

                    const newCredentialList = createCredential(
                        issuerDID,
                        subjectDID,
                        credentialSubject,
                        ["StatusList2021"]
                    );

                    const options = {
                        url: `${listUrl}/statusList`,
                        method: "POST",
                        data: newCredentialList,
                    };
                    await axios(options);
                    return true;
                })
                .catch((error: any) => {
                    console.log(error);
                    return false
                });
        }
    }

    return false
}

/**
 * Helper function to retrieve the Issuer DID from a Verifiable Credential
 * 
 * @param vc the Verifiable Credential
 * @returns Issuer DID if it exists
 */
export function getIssuerFromVC(vc: VerifiableCredential): DID | undefined {
    const jwtService = new JWTService()
    if(typeof vc === 'string') {
        const credential = jwtService.decodeJWT(vc)?.payload as JWTPayload
        return credential.iss
    } else {
        return vc.issuer.id
    }
}

/**
 * Helper function to retrieve Subject DID from a Verifiable Credential
 * 
 * @param vc the Verifiable Credential
 * @returns Subject DID if it exists
 */
export function getSubjectFromVP(vc: VerifiableCredential): DID | undefined {
    const jwtService = new JWTService()
    if(typeof vc === 'string') {
        const credential = jwtService.decodeJWT(vc)?.payload as JWTPayload
        return credential.sub as string
    } else {
        return vc.credentialSubject.id
    }
}

/**
 * Data model for the [`credentialSubject`](https://www.w3.org/TR/vc-data-model/#credential-subject)
 * property of the Verifiable Credential
 */
export interface CredentialSubject {
    // eslint-disable-next-line  @typescript-eslint/no-explicit-any
    [property: string]: any;
}
