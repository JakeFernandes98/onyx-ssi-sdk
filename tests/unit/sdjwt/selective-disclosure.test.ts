import { assert } from "console"
import { EthrDIDMethod, JWT, JWTService, KeyDIDMethod, PROOF_OF_NAME, SALT_BYTE_SIZE, createDisclosures, encodeDisclosure, getSupportedResolvers, hashDisclosure, ianaToCryptoAlg, parseDisclosure } from "../../../src/services/common"
import { KEY_ALG } from "../../../src/utils"
import * as crypto from 'crypto'
import * as jose from 'jose'
import { JwtCredentialPayload, JwtPresentationPayload } from "did-jwt-vc"
import { createAndSignCredentialJWT, createAndSignCredentialSDJWT, createCredential } from "../../../src/services/issuer/credential"
import { createAndSignPresentationSDJWT } from "../../../src/services/holder/presentation"
import { verifyCredentialJWT, verifyPresentationSDJWT } from "../../../src/services/verifier/verification"


describe('selective disclosure utilities', () => {

    const jwtService = new JWTService()

    const didEthrWithKeys = {
        did: 'did:ethr:maticmum:0xA765CFD161AA0B6f95cb1DC1d933BFf6FAb0ABeE',
        keyPair: {
            algorithm: KEY_ALG.ES256K,
            publicKey: '027b942c04885bfdcc2497a9a94b2bdf915483cc2c5b5bffd7e86dcf021d731855',
            privateKey: '0x40dd06c69267386d198939c64580714e9526cea274f13f76b6b16e431d7caaa9'
        }
    }
    const keyDIDMethod = new KeyDIDMethod()
    const ethrDIDMethod = new EthrDIDMethod({
        name: 'maticmum',
        rpcUrl: 'https://rpc-mumbai.maticvigil.com/', 
        registry: "0x41D788c9c5D335362D713152F407692c5EEAfAae"})
    let didHolder
    let combinedResolver


    beforeAll(async () => {
        didHolder = await keyDIDMethod.create()
        combinedResolver = getSupportedResolvers([keyDIDMethod, ethrDIDMethod])
    })
    

    it('returns the right crypto algorithm for both did:ethr and did:key', async () => {
        const didKeyWithKeys = await keyDIDMethod.create()
        const convertedEthr = jwtService.convertKeys(didEthrWithKeys)
        const converedKey = jwtService.convertKeys(didKeyWithKeys)
        const ethrAlg = ianaToCryptoAlg(convertedEthr.alg!)
        const keyAlg = ianaToCryptoAlg(converedKey.alg!)
        expect(ethrAlg).toEqual('sha256')
        expect(keyAlg).toEqual('sha512')

    })

    it('should add disclosures to exisiting VC JWT', async () => {
        const hashAlg = 'ES256K'
        const subjectData = {
            'fname' : 'John',
            'sname' : 'Doe',
            'nationalId': 'ajj3i23293f290'
        }
        const credential = await createAndSignCredentialJWT(didEthrWithKeys, didHolder.did, subjectData, [PROOF_OF_NAME])
        const target =  jwtService.decodeJWT(credential)!.payload as JwtCredentialPayload

        const claimValues = {
            'fname' : 'John',
            'sname' : 'Doe',
        }

        const { target: updatedTarget, _disclosures } = createDisclosures(hashAlg, claimValues, target);
    
        expect(_disclosures).toHaveLength(2);
        expect(updatedTarget.vc.credentialSubject).toHaveProperty('_sd');
        expect(updatedTarget.vc.credentialSubject._sd).toHaveLength(2);
    })
    
    let credential: JWT
    let jwt: JWT
    let disclosures: string[]

    it('correctly creates and signs a SD-JWT', async () => {
        const subjectData = {
            'fname' : 'John',
            'sname' : 'Doe',
            'nationalId': 'ajj3i23293f290'
        }
        const claimValues = {
            'fname' : 'John',
            'sname' : 'Doe',
        }
        credential = await createAndSignCredentialSDJWT(didEthrWithKeys, didHolder.did, subjectData, [PROOF_OF_NAME], claimValues)
        expect(credential).toBeDefined()
        expect(credential).toContain("~")
        jwt = credential.split("~")[0]
        // console.log(credential)
        const payload = jwtService.decodeJWT(jwt)!.payload as JwtCredentialPayload
        expect(payload.vc.credentialSubject).toHaveProperty('_sd')
        expect(payload.vc).toHaveProperty('_sd_alg')
        expect(payload.vc.credentialSubject._sd).toHaveLength(2)
        disclosures = credential.split("~").splice(1)
        expect(disclosures).toHaveLength(2)
    })

    let payloadZero
    let disclosuresZero
    let presentationZero
    it('holder correctly creates a Verifiable presentation with no claims', async () => {
        presentationZero = await createAndSignPresentationSDJWT(didHolder, [credential], [[]])
        jwt = presentationZero.split("~")[0]
        payloadZero = jwtService.decodeJWT(jwt)!.payload as JwtPresentationPayload
        expect(payloadZero.vp.verifiableCredential).toBeDefined()
        expect(payloadZero.vp.verifiableCredential).toHaveLength(1)
        const decodedVc = jwtService.decodeJWT(payloadZero.vp.verifiableCredential![0] as string)!.payload as JwtCredentialPayload
        expect(decodedVc.vc.credentialSubject).toHaveProperty('_sd')
        expect(decodedVc.vc).toHaveProperty('_sd_alg')
        expect(decodedVc.vc.credentialSubject._sd).toHaveLength(2)


        disclosuresZero = presentationZero.split("~").splice(1)
        
    })

    it("and be verified", async () => {
        const res = await verifyPresentationSDJWT(presentationZero, combinedResolver)
        expect(res.vp.verified).toBeTruthy()
        
    })

    let payloadOne
    let disclosuresOne
    let presentationOne
    it('holder correctly creates a Verifiable presentation with one claim', async () => {
        presentationOne = await createAndSignPresentationSDJWT(didHolder, [credential], [['fname']])
        jwt = presentationOne.split("~")[0]
        payloadOne = jwtService.decodeJWT(jwt)!.payload as JwtPresentationPayload
        expect(payloadOne.vp.verifiableCredential).toBeDefined()
        expect(payloadOne.vp.verifiableCredential).toHaveLength(1)
        const decodedVc = jwtService.decodeJWT(payloadOne.vp.verifiableCredential![0] as string)!.payload as JwtCredentialPayload
        expect(decodedVc.vc.credentialSubject).toHaveProperty('_sd')
        expect(decodedVc.vc).toHaveProperty('_sd_alg')
        expect(decodedVc.vc.credentialSubject._sd).toHaveLength(2)


        disclosuresOne = presentationOne.split("~").splice(1)
    })

    it("and be verified", async () => {
        const res = await verifyPresentationSDJWT(presentationOne, combinedResolver)
        expect(res.vp.verified).toBeTruthy()
        expect(res.disclosed[0]).toHaveProperty('fname')
    })


    let payloadTwo
    let disclosuresTwo
    let presentationTwo
    it('holder correctly creates a Verifiable presentation with both claims', async () => {
        presentationTwo = await createAndSignPresentationSDJWT(didHolder, [credential], [['fname','sname']])
        jwt = presentationTwo.split("~")[0]
        payloadTwo = jwtService.decodeJWT(jwt)!.payload as JwtPresentationPayload
        expect(payloadTwo.vp.verifiableCredential).toBeDefined()
        expect(payloadTwo.vp.verifiableCredential).toHaveLength(1)
        const decodedVc = jwtService.decodeJWT(payloadTwo.vp.verifiableCredential![0] as string)!.payload as JwtCredentialPayload
        expect(decodedVc.vc.credentialSubject).toHaveProperty('_sd')
        expect(decodedVc.vc).toHaveProperty('_sd_alg')
        expect(decodedVc.vc.credentialSubject._sd).toHaveLength(2)


        disclosuresTwo = presentationTwo.split("~").splice(1)
    })

    it("and be verified", async () => {
        const res = await verifyPresentationSDJWT(presentationTwo, combinedResolver)
        expect(res.vp.verified).toBeTruthy()
        expect(res.disclosed[0]).toHaveProperty('fname')
        expect(res.disclosed[0]).toHaveProperty('sname')
    })

    // it("verifier can verify and read presentation with no claims", async () => {

    //     expect(disclosuresZero).toHaveLength(1)
    //     expect(disclosuresZero[0]).toBe("")

    //     const res = await verifyCredentialJWT(payloadZero.vp.verifiableCredential![0], combinedResolver)
    //     expect(res).toBeTruthy()

    // })

    // it("verifier can verify and read presentation with one claim", async() => {
    //     const decodedVc = jwtService.decodeJWT(payloadOne.vp.verifiableCredential![0] as string)!.payload as JwtCredentialPayload
        
    //     expect(disclosuresOne).toHaveLength(1)
    //     expect(disclosuresOne[0]).toBe(credential.split("~").splice(1)[0])
        
    //     let claim = checkDisclosure(decodedVc.vc._sd_alg, decodedVc.vc.credentialSubject._sd, disclosuresOne[0])
    //     console.log(claim)
    //     expect(claim).toBe("John")

    //     const res = await verifyCredentialJWT(payloadOne.vp.verifiableCredential![0], combinedResolver)
    //     expect(res).toBeTruthy()
        
    // })

    // it("verifier can verify and read presentation with both claims", async() => {
    //     const decodedVc = jwtService.decodeJWT(payloadTwo.vp.verifiableCredential![0] as string)!.payload as JwtCredentialPayload

    //     expect(disclosuresTwo).toHaveLength(2)

    //     expect(disclosuresTwo[0]).toBe(credential.split("~").splice(1)[0])
    //     let claim = checkDisclosure(decodedVc.vc._sd_alg, decodedVc.vc.credentialSubject._sd, disclosuresTwo[0])
    //     expect(claim).toBe("John")


    //     expect(disclosuresTwo[1]).toBe(credential.split("~").splice(1)[1])
    //     let claim2 = checkDisclosure(decodedVc.vc._sd_alg, decodedVc.vc.credentialSubject._sd, disclosuresTwo[1])
    //     expect(claim2).toBe("Doe")

    //     const res = await verifyCredentialJWT(payloadTwo.vp.verifiableCredential![0], combinedResolver)
    //     expect(res).toBeTruthy()
        
    // })

    


})