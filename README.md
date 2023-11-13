# Onyx SSI SDK Fork

## Motivation

We decided to focus on implementing selective disclosure and revocation as part of the Onyx SDK hackathon. We chose these two features as we believe they gave us tools to implement interesting and powerful use cases for our POC.

Selective Disclosure was initially implemented according to the SD-JWT spec, which can be found at this hash commit ``

However, slight modifications were made to the standard to allow the presentation and verification of multiple SD-JWTs as part of a single W3C Verifiable Presentation which is code found in the lasest commit of this fork.

Forming a SD-JWT presentation usually takes the form of:

VPJWT~disclosure1~disclosure2...

Which limits us to only presenting a single credential at a time. And so we have changed the way an SD-JWT presentation is formatted to look like the following:

VPJWT~vc1_disclousre1~vc1_disclosure2&vc2_disclosure1&&vc4_disclousure1

Not only does this let us include multiple disclosures for multiple SD-enabled credentials, but also lets us mix and match normal VC JWTs with SD-JWTs. The drawbacks being that this is not part of any standard and it assumes the order of the credentials within the VPJWT is being maintained and respected through out the end to end flow.

For revocation we have implemented StatusList2021 to support credential revocation according to that standard, which allows us to issue and revoke credentials using did:key now as well as did:ethr and removes the need to register the DID to the DIDRegistry for ethr.

## Implementation

Unfortunatley, I began the implementation before seeing the ReadMe on the main branch for the SD-JWT challenge, This means the structure of the implementation differs. Rather than having all the code centralised to a single file (sdjwt.ts), it is spread around utilising the exisiting structure of jwtService, issuer, holder and verifier. At the time this felt like the more appropriate approach. Unit tests have been written to the test the functionality in the respective test files.

## Running the fork
    
1. Clone this repo
2. run npm install
3. npm run build
4. npm link

Now in the terminal navigate to the codebase you want to use the repo and run
```npm link @jpmorganchase/onyx-ssi-sdk```

This should add a line like this to your package.json
```
"dependencies": {
    "@jpmorganchase/onyx-ssi-sdk": "file:../onyx-ssi-sdk",
}
```

If you need to make code changes to the fork, you will need to run npm run build again once you are finished (but you don't need to do the redo the link process)



# Original ReadMe


Create SSI Ecosystems following W3C Standards for [Verifiable Credentials](https://www.w3.org/TR/vc-data-model/) and [DIDs](https://www.w3.org/TR/did-core/)

* Create and verify Verifiable Credentials and Verifiable Presentations
* Support for [did:ethr](https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md) and [did:key](https://w3c-ccg.github.io/did-method-key/)
* Support for JWT as digital proof
* Support for Verifiable Credential Schemas

## How to Use REPO

### Prerequisites

* Nodejs v16

### Installation

``` shell
npm install @jpmorganchase/onyx-ssi-sdk
```

### Build

This project is built to support both CommonJS and ECMAScript Module Formats

The CommonJS format is configured in `configs/tsconfig.cjs.json` and the ECMAScript is configured in `configs/tsconfig.esm.json` 

``` shell
npm install
npm run build
```
### Tests

Unit Tests: `npm run test`

Hardhat: 
``` shell 
npx hardhat compile
npx hardhat test
```

## Navigating the SDK
* [DID Management](https://github.com/jpmorganchase/onyx-ssi-sdk/tree/main/src/services/common/did): Create, Resolve, Update, and Delete the 2 supported DID Methods (did:key and did:ethr)
* [Credential Schema Management](https://github.com/jpmorganchase/onyx-ssi-sdk/tree/main/src/services/common/schemas): Example of 4 Credential Types and their schemas as well as helper methods for Schema Management
* [JWT Signatures](https://github.com/jpmorganchase/onyx-ssi-sdk/tree/main/src/services/common/signatures): Sign Verifiable Credentials as JWTs
* [Issuer](https://github.com/jpmorganchase/onyx-ssi-sdk/tree/main/src/services/issuer): All functionality required to be a Credential Issuer
* [Holder](https://github.com/jpmorganchase/onyx-ssi-sdk/tree/main/src/services/holder): All functionality required to be a Credential Holder
* [Verifier](https://github.com/jpmorganchase/onyx-ssi-sdk/tree/main/src/services/verifier): All functionality to perform basic Credential verification
* [KeyUtils](https://github.com/jpmorganchase/onyx-ssi-sdk/blob/main/src/utils/KeyUtils.ts): Helper functions for SDK supported keys

## Full SSI Ecosystem Example

For examples of how to use the SDK, check out our [onyx-ssi-sdk-examples repo](https://github.com/jpmorganchase/onyx-ssi-sdk-examples)

Below code shows the Issuance, Claiming, and Verification of W3C Credential/Presentation.

```shell

//DID Key
const didKey = new KeyDIDMethod()

//DID Ethr configs
const ethrProvider = {
    name: 'maticmum', 
    rpcUrl: 'https://rpc-mumbai.maticvigil.com/', 
    registry: "0x41D788c9c5D335362D713152F407692c5EEAfAae"}
   
console.log('-----------------VC Issuance---------------')
       
//create DID for Issuer (did:ethr)
const didEthr = new EthrDIDMethod(ethrProvider)
const issuerEthrDid = await didEthr.create();
   
//create DID for Holder of Credential (did:key)
const holderDID = await didKey.create();
   
//create DID for VC to support Revocation of Credential
const vcDID = await didEthr.create();
   
//Create a 'Proof of Name' VC
const subjectData = {
    "name": "Ollie"
}
   
//Additonal parameters can be added to VC including:
//vc id, expirationDate, credentialStatus, credentialSchema, etc
const additionalParams = {
    id: vcDID.did,
    expirationDate: "2024-01-01T19:23:24Z",
}
   
const vc = await createCredential(
    issuerEthrDid.did, holderDID.did, subjectData, PROOF_OF_NAME, additionalParams)
console.log(JSON.stringify(vc, null, 2))
   
const jwtService = new JWTService()
const jwtVC = await jwtService.signVC(issuerEthrDid, vc)
console.log(jwtVC)
   
console.log('-----------------VC Presentation---------------')
   
//Create Presentation from VC JWT
const vp = await createPresentation(holderDID.did, [jwtVC])
console.log(JSON.stringify(vp, null, 2))
   
const jwtVP = await jwtService.signVP(holderDID, vp)
console.log(jwtVP)
   
console.log('----------------------VERIFY VC/VP------------------')
       
//create DID resolvers
const ethrResolver = getEthrResolver(ethrProvider)
const keyResolver = getKeyResolver()
const didResolver = new Resolver({
    ...ethrResolver, 
    ...keyResolver})
   
   
//Verify VC JWT from Issuer
const resultVc = await verifyCredentialJWT(jwtVC, didResolver)
console.log(resultVc)
       
//Verify VP JWT from Holder
const resultVp = await verifyPresentationJWT(jwtVP, didResolver)
console.log(resultVp)
```

## Open Source Identity Packages
* [did-resolver](https://github.com/decentralized-identity/did-resolver)
* [ethr-did-resolver](https://github.com/decentralized-identity/ethr-did-resolver)
* [key-did-resolver](https://github.com/ceramicnetwork/js-did/tree/main/packages/key-did-resolver)
* [did-jwt-vc](https://github.com/decentralized-identity/did-jwt-vc)
* [did-jwt](https://github.com/decentralized-identity/did-jwt)

## Standards and Specifications
* [W3C Verifiable Credentials 1.0](https://www.w3.org/TR/vc-data-model/)
* [Decentralized Identifiers v1.0](https://w3c.github.io/did-core/)
* [did:key spec](https://w3c-ccg.github.io/did-method-key/)
* [did:ethr spec](https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md)

