import { createCipheriv, createDecipheriv, pbkdf2Sync, generateKeyPair, createVerify, createSign, createHash, constants, sign, verify } from 'crypto'
import * as dotenv from 'dotenv'
import { signDocumentsPermissions } from '../utils/constants.js';
import { isValidJSON, statusAndError } from '../utils/functions.js';
import { updateUserById } from './DB.js';
dotenv.config()

class CipherSingleton {

    static instance;
    #aes256Key
    #aes256Iv
    #appKey
    #appToken
    #signDocumentsPermissions
    constructor(signDocumentsPermissions){
        if(CipherSingleton.instance)
            return CipherSingleton.instance
        
        this.#aes256Key = process.env.KEY;
        this.#aes256Iv = process.env.IV
        this.#appKey = this.#sha256(process.env.APP_KEY)
        this.#appToken = this.#sha256(process.env.APP_TOKEN)
        this.#signDocumentsPermissions = signDocumentsPermissions
        CipherSingleton.instance = this
    }

    async RSAGenerateKeyPair(){
        return new Promise((resolve, reject) => {
            generateKeyPair('rsa', {
                modulusLength: 2048, // Length of key in bits
                publicKeyEncoding: {
                    type: 'spki', // Recommended to use 'spki' for public key
                    format: 'pem', // Format for public key
                },
                privateKeyEncoding: {
                    type: 'pkcs8', // Recommended to use 'pkcs8' for private key
                    format: 'pem', // Format for private key
                }
            }, (err, publicKey, privateKey) => {
                if (err) {                    
                    return reject(err); // Reject the promise on error
                }                                
                resolve([ publicKey, privateKey ]); // Resolve with the keys
            });
        });
    }

    #sha256(input) {
        // Create a SHA-256 hash object
        const hash = createHash('sha256');
        hash.update(input);
        // Return it as a hexadecimal string
        return hash.digest('hex');
    }

    CheckClientHeaders(clientAppKey, clientAppToken){        
        return new Promise((resolve, reject) => {
            if(clientAppKey === this.#appKey &&
            clientAppToken === this.#appToken){
               resolve(true)
            }else{
               if(!process.env.APP_KEY || !process.env.APP_TOKEN){
                   reject({
                    message: "Internal Server Error",
                    status: 500
                   })
               }else if(!clientAppKey || !clientAppToken){
                   reject({
                    message: "Missing credentials",
                    status: 401
                   })
               }else{
                    reject({
                        message: "Wrong credentials",
                        status: 403
                    })
               }
            }

        })
    }
       
    // Store the encrypted keys in the database
    async #storeKeysInDatabase(userId, jwtpublickey, jwtprivateencryptedkey, documentpublickey, documentprivateencryptedkey){
        return new Promise(async(resolve, reject) => {
            try {
                let payload = undefined
                if(jwtpublickey && documentpublickey){
                    payload = {
                        jwtpublickey,
                        jwtprivateencryptedkey,
                        documentpublickey,
                        documentprivateencryptedkey
                    };
                }else if(jwtpublickey){
                    payload = {
                        jwtpublickey,
                        jwtprivateencryptedkey
                    }
                }else if(documentpublickey){
                    payload = {
                        documentpublickey,
                        documentprivateencryptedkey
                    }
                }

                if(payload){
                    await updateUserById(userId, storedData)
                }
                resolve("ok")
            } catch (error) {
                reject(error)   
            }
        })
    }


    // Called on login, after user has been created
    async createJWT(payload, jwtPrivateKey){ 
        return new Promise(async(resolve, reject ) => {
            try {

                const header = JSON.stringify({ alg: 'RS256', typ: 'JWT' });
                const base64Header = Buffer.from(header).toString('base64url');
                const base64Payload = Buffer.from(JSON.stringify(payload)).toString('base64url');
            
                const signatureInput = `${base64Header}.${base64Payload}`;
                const signature = sign('RSA-SHA256', Buffer.from(signatureInput), {
                    key: jwtPrivateKey,
                    padding: constants.RSA_PKCS1_PSS_PADDING,
                });
            
                const base64Signature = signature.toString('base64url');
                resolve(`${signatureInput}.${base64Signature}`);             
            } catch (error) {   
                reject(statusAndError(error))
            }
        })
    }

    async #decodeJWT(JWTtoken){
        return new Promise((resolve, reject) => {
            try {
                const [header64, payload64, signature64] = JWTtoken.split('.');
                const signatureInput = `${header64}.${payload64}`;                
                // Decode the header and payload
                const payload = JSON.parse(Buffer.from(payload64, 'base64url').toString());
                resolve([ payload, signatureInput, signature64 ])
            } catch (error) {
                reject({status:401, message:"Error decoding JWT -- "+error?.message ?? JSON.stringify(error)})
            }
        })

    }

    async getSessionData(JWTtoken) {
        return new Promise(async (resolve, reject) => {
            try {
                const [payload] = await this.#decodeJWT(JWTtoken);
    
                if (payload) {
                    resolve(payload);
                } else {
                    reject({ status: 401, message: "Invalid session" });
                }
            } catch (error) {
                reject({ status: error?.status ?? 500, message: "Error getting session -- " + (error?.message ?? JSON.stringify(error)) });
            }
        });
    }


    // Called from client, returns always a token, if fails back to login
    async validateJWT(ip,jwt, jwtpublickey){
        return new Promise(async(resolve, reject) => {
            try {
                const [payload, signatureInput, signature64 ] = await this.#decodeJWT(jwt);
                
                if (payload.ip !== ip) {
                    reject({ status: 401, message: "Changed IP" });
                }
                // Verify the signature
                const isValid = verify(
                    'RSA-SHA256',
                    Buffer.from(signatureInput),    // Input made of headers and payloads
                    {       
                        key: jwtpublickey,
                        padding: constants.RSA_PKCS1_PSS_PADDING,
                    },
                    Buffer.from(signature64, 'base64url') // Signature itself
                );
                resolve(isValid ? payload : false)
            } catch (error) {
                reject({ status: 500, message: "Error verifying token: " + (error?.message ?? error) });
            }
        });
    }


    async RSAsignDocument(privateKey, dataToVerify){
        return new Promise(async(resolve,reject) => {
            try {
                
                
                // const [
                //     { documentprivateencryptedkey, documentpublickey:publicKey },
                //     { applicant, manager }
                // ] = await Promise.all([getUserById(userId), this.#getDocument(type, docId)])
                // console.log(documentprivateencryptedkey, publicKey, applicant, manager, "DATA");
                
                // if((userId !== applicant && userId !== manager) | (!documentprivateencryptedkey | !documentprivateencryptedkey))
                //     return reject({message:"Not allowed", status:403})
                // // Get signer RSA keys
                // const privateKey = await this.AES256decrypt(documentprivateencryptedkey.toString('utf-8'), userId)
                const sign = createSign('SHA256');
                sign.update(dataToVerify);
                sign.end();
                const signature = sign.sign(privateKey, 'hex');  
                resolve(signature)              
            } catch (error) {
                console.log(error);                
                reject(error)
            }
        })

    }
    
    // Method to verify data
    async RSAverifySignature(dataToVerify, publicKey, signature){
        return new Promise((resolve, reject) => {
            try {
                // Convert signature from hex to buffer
                const signatureBuffer = Buffer.from(signature).toString('utf-8');
                console.log(signatureBuffer, "signatureBuffer");
                const verify = createVerify('SHA256');
                verify.update(dataToVerify);
                verify.end();
                resolve(verify.verify(publicKey, signatureBuffer, 'hex'));
            } catch (error) {
                reject({message:"Error verifying signature -- details: "+error?.message ?? JSON.stringify(error), status: 500})
            }
        })
    }

    #generateKeyAndIv(salt){
        return [pbkdf2Sync(this.#aes256Key, salt, 100000, 32, 'sha512'), pbkdf2Sync(this.#aes256Iv, salt, 100000, 16, 'sha512')]
    }
    
    async AES256encrypt(text, salt){        
        return new Promise((resolve, reject) => {
            try {
                const [key, iv] = this.#generateKeyAndIv(salt)
                const cipher = createCipheriv('aes-256-cbc', key, iv)
                if(typeof text === "object"){
                    text = JSON.stringify(text)
                }                
                resolve(cipher.update(text, 'utf-8', 'hex') + cipher.final('hex'))
            } catch (error) {
                reject({message: "An error occurred while AES encrypting -- details: " + error?.message, status:403})
            }
        })
    }

    async AES256decrypt(cryptedText, salt){
        return new Promise((resolve, reject) => {
                try {
                const [key, iv] = this.#generateKeyAndIv(salt)
                const decipher = createDecipheriv('aes-256-cbc', key, iv);
                const decryptedValue = decipher.update(cryptedText, 'hex', 'utf8') + decipher.final('utf8')
                let stringifyIfNeeded = isValidJSON(decryptedValue) ? JSON.parse(decryptedValue) : decryptedValue
                resolve(stringifyIfNeeded)
            } catch (error) {
                reject({message:"Error trying to AES256decrypt -- details: "+error?.message ?? JSON.stringify(error), status: 500})
            }
        })

    }
}

const Cipher = new CipherSingleton(signDocumentsPermissions)
export default Cipher


/*
                   id                  |              applicant               |               manager
--------------------------------------+--------------------------------------+--------------------------------------
 54692017-d378-487d-9e0a-a942a1beae8b | 7d17333e-fc0c-4765-8dac-b0bae6cff848 | a5fd6d33-d27c-48ba-8bff-92dc14bbebb3
*/