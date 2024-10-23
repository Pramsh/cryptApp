import { getUsers } from "../../lib/DB";
import DecryptUserData from "../../middlewares/DecryptUserData"
import EncryptUserData from "../../middlewares/EncryptUserData"
import RSA_Gen from "../../middlewares/RSA_Gen"
import { signDocumentsPermissions, userPermissions } from "../../utils/constants";
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
    describe("Generates RSA for asymmetric signatures for all users", () => {
        jest.setTimeout(30000); // Increase timeout to 30 seconds
        it("Returns ok and status 200", async () => {
            const userIds = await getUsers()
            expect(userIds).toBeInstanceOf(Array);
            expect(userIds.length).toBeGreaterThan(0);
            for(let el of userIds){
                expect(typeof el).toBe('object');
                rsa_genMockReq.body.userId = el.id
                await RSA_Gen(rsa_genMockReq, rsa_genMockRes)
                expect(rsa_genMockRes.send).toHaveBeenCalledWith("ok")
                expect(rsa_genMockRes.status).toHaveBeenCalledWith(200)
            }
        })

        //test to generate one key per each kind of role
        it("Generates one RSA key per each kind of role", async () => {
            const userIds = await getUsers()
            expect(userIds).toBeInstanceOf(Array);
            expect(userIds.length).toBeGreaterThan(0);
            const roles = {}
            for(let el of userIds){
                expect(typeof el).toBe('object');
                if(!roles[el.role] && userPermissions.some((permission) => el.role === permission)){
                    if((signDocumentsPermissions.some((r) => r === el.role) && !el.documentpublickey) || ((!signDocumentsPermissions.some((r) => r === el.role) && !el.documentpublickey && !el.jwtpublickey))){                        
                        roles[el.role] = true
                        rsa_genMockReq.body.userId = el.id
                        await RSA_Gen(rsa_genMockReq, rsa_genMockRes)
                        expect(rsa_genMockRes.send).toHaveBeenCalledWith("ok")
                        expect(rsa_genMockRes.status).toHaveBeenCalledWith(200)
                    }
                }
            }
            //warn if there is not one user tested for each role, but don't error
            console.log("No available users to test for roles:", userPermissions.filter((role) => !roles[role]).join(", "))
        })
    })

    
})
