import { getUsersIds } from "../../lib/DB";
import DecryptUserData from "../../middlewares/DecryptUserData"
import EncryptUserData from "../../middlewares/EncryptUserData"
import RSA_Gen from "../../middlewares/RSA_Gen"
import {
    testEncryptDecryptStr,
    testEncryptDecryptObject,
    testEncryptDecryptArray,
    encryptMockReqString,
    encryptMockResString,
    decryptMockReqString,
    decryptMockResString,
    encryptMockReqNumber,
    encryptMockResNumber,
    encryptMockReqBoolean,
    encryptMockResBoolean,
    encryptMockReqObject,
    encryptMockResObject,
    decryptMockReqObject,
    decryptMockResObject,
    encryptMockReqArray,
    encryptMockResArray,
    decryptMockReqArray,
    decryptMockResArray,
    rsa_genMockReq,
    rsa_genMockRes
} from '../utils/cipher_mock';

describe("Cypher", () => {
    describe("AES256", ()=>{

        describe('If encrypts and decrypts more data types and returns 200', ()=> {

            it("Strings", async () => {
                await EncryptUserData(encryptMockReqString, encryptMockResString)
                const encryptedData = encryptMockResString.send.mock.calls[0][0]
                expect(encryptMockResString.send).toHaveBeenCalledWith(expect.any(String))
                expect(encryptMockResString.status).toHaveBeenCalledWith(200)
                
                decryptMockReqString.body.data = encryptedData
                await DecryptUserData(decryptMockReqString,decryptMockResString)
                expect(decryptMockResString.send).toHaveBeenCalledWith(testEncryptDecryptStr)                
            })

            it("Objects", async () => {
                await EncryptUserData(encryptMockReqObject, encryptMockResObject)
                const encryptedData = encryptMockResObject.send.mock.calls[0][0]
                expect(encryptMockResObject.send).toHaveBeenCalledWith(expect.any(String))
                expect(encryptMockResObject.status).toHaveBeenCalledWith(200)
                
                decryptMockReqObject.body.data = encryptedData
                await DecryptUserData(decryptMockReqObject, decryptMockResObject)
                expect(decryptMockResObject.send).toHaveBeenCalledWith(testEncryptDecryptObject)
            })

            it("Arrays", async () => {
                await EncryptUserData(encryptMockReqArray, encryptMockResArray)
                const encryptedData = encryptMockResArray.send.mock.calls[0][0]
                expect(encryptMockResArray.send).toHaveBeenCalledWith(expect.any(String))
                expect(encryptMockResArray.status).toHaveBeenCalledWith(200)
                
                decryptMockReqArray.body.data = encryptedData
                await DecryptUserData(decryptMockReqArray, decryptMockResArray)
                expect(decryptMockResArray.send).toHaveBeenCalledWith(testEncryptDecryptArray)
            })
        
        })

        describe('If encrypts boolean and number data types returns 403', ()=> {

            it("Booleans", async () => {
                await EncryptUserData(encryptMockReqBoolean, encryptMockResBoolean)
                expect(encryptMockResBoolean.status).toHaveBeenCalledWith(403)
            })

            it("Numbers", async () => {
                await EncryptUserData(encryptMockReqNumber, encryptMockResNumber)
                expect(encryptMockResNumber.status).toHaveBeenCalledWith(403)
            })
        
        })        
    })
})


describe("RSA", () => {
    describe("Generates RSA for asynchrouns operations", () => {
        it("Returns ok and status 200", async () => {
            await getUsersIds()
            const [ id ] = rsa_genMockRes.send.mock.calls[0][0]
            rsa_genMockReq.id = id
            await RSA_Gen(rsa_genMockReq, rsa_genMockRes)
            expect(rsa_genMockRes.send).toHaveBeenCalledWith("ok")
            expect(rsa_genMockRes.status).toHaveBeenCalledWith(200)
        })
    })
})
