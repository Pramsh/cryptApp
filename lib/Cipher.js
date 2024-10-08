import { createCipheriv, createDecipheriv, pbkdf2Sync, generateKeyPair, createVerify, createSign, createHash, constants, sign, verify } from 'crypto'
import * as dotenv from 'dotenv'
import { JWTexpirationTimeValue, signDocumentsPermissions, maxRefreshToken } from '../utils/constants.js';
import { JWTexpirationTime, isValidJSON, statusAndError, checkVariables } from '../utils/functions.js';
import { updateUserById, getUserById, updateDocApplicantOrManagerSignature } from './DB.js';
dotenv.config()

class CipherSingleton {

    static instance;
    #aes256Key
    #aes256Iv
    #appKey
    #appToken

    constructor(){
        if(CipherSingleton.instance)
            return CipherSingleton.instance
        
        this.#aes256Key = process.env.KEY;
        this.#aes256Iv = process.env.IV
        this.#appKey = this.#sha256(process.env.APP_KEY)
        this.#appToken = this.#sha256(process.env.APP_TOKEN)

        CipherSingleton.instance = this
    }

    async #RSAGenerateKeyPair(){
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

    #hasPermissionForSignDocumentKey(permission){
        return signDocumentsPermissions.some((perm) => perm === permission)
    }

    // Called on login, after user has been created
    async createJWT(ip, token_version, {id, email, role, jwtprivateencryptedkey}) {
        return new Promise(async(resolve, reject ) => {
            try {

                await checkVariables( [ip, token_version, id, email, role, jwtprivateencryptedkey])


                if(!email || !role || !jwtprivateencryptedkey){
                    ({ email, role, jwtprivateencryptedkey } = await getUserById(id))
                } 
                
                const payload = {
                    id,
                    email,
                    role,
                    ip,
                    token_version: token_version,
                    exp:JWTexpirationTime(), // Expiration 1h
                };
                // Decrypt key                
                const jwtPrivateKey = await this.AES256decrypt(jwtprivateencryptedkey.toString("utf-8"), id)
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
                reject(statusAndError(error?.message ?? error))
            }
        })
    }

    #decodeJWT(JWTtoken){
        const [header64, payload64, signature64] = JWTtoken.split('.');
        const signatureInput = `${header64}.${payload64}`;                
        // Decode the header and payload
        const payload = JSON.parse(Buffer.from(payload64, 'base64url').toString());
        return [ payload, signatureInput, signature64 ]

    }

    async getSessionInfo(headers, JWTtoken){
        return new Promise((resolve, reject) => {
            try {
              this.validateJWT(headers,JWTtoken)
                .then(() => {
                    const [ payload ] = this.#decodeJWT(JWTtoken)
                    resolve(payload)
                })
                .catch((e) => reject({...e, message: "Invalid session -- "+e?.message}))                 
            } catch (error) {
                reject({status:error?.status??401,message:"Error getting user session -- "+error?.message ?? JSON.stringify(error)})
            }
        })
    }

    #timesExpired(expiration, currentTime){
        return Math.floor((-1) * ( expiration - currentTime ) / JWTexpirationTimeValue)
    }

    // Called from client, returns always a token, if fails back to login
    async validateJWT(ip,JWTtoken){
        return new Promise(async(resolve, reject) => {
            try {
                const [payload, signatureInput, signature64 ] = this.#decodeJWT(JWTtoken);
                const currentUserId = payload.id;
                const { jwtpublickey, jwtprivateencryptedkey, email, role } = await getUserById(currentUserId);

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
    
                // Check if the token is valid
                if (!isValid) {
                    return reject({ status: 401, message: "Invalid token signature." });
                }

                if (payload.token_version > maxRefreshToken){
                    return reject({ status: 403, message: "Token limit reached." });
                }
         
                if (payload.ip !==  ip){
                    return reject({ status: 401, message: "Changed IP." });
                }
                
                const currentTime = Math.floor(Date.now() / 1000);
                
                // If expired more than 1 times  
                if (Math.sign(payload.exp -  currentTime) === -1 && this.#timesExpired(payload.exp, currentTime) > 1){
                    return reject({ status: 401, message: "Invalid token." });
                }
   
                // If expired one time
                if (payload.exp < currentTime) {
                  
                    const newData = { email, role }
                    const oldData = { email:payload.email, role:payload.role }
                                        
                    // Check if old user data correspond to new    
                    if(JSON.stringify(newData) === JSON.stringify(oldData)){

                        // Generate new token and return it to the client
                        return this.createJWT(ip, payload.token_version + 1, {id:currentUserId,  email, role, jwtprivateencryptedkey})
                            .then((newToken) => resolve(newToken))
                            .catch((err) => reject(err))
                    }else return reject({ status: 401, message: "Token has expired and user data has changed." });
                }
        
                if (!payload.role){
                    return reject({ status: 403, message: "Required permissions." });
                }
                    
                resolve(JWTtoken)
            } catch (error) {
                reject({ status: 500, message: "Error verifying token: " + (error?.message ?? error) });
            }
        });
    }

    // Called by the login service, returns the JWT
    // Called only if the user is new (maybe also if permissions have changed in the DB)
    // If permissions have changed, only new keys should be generated, old ones should remain the same
    async RSAhandleGeneration(userId){ 
        return new Promise(async(resolve, reject) => {
            try {                
                
                const userData = await getUserById(userId)
                
                // Skip if user already has both keys
                if( userData.jwtprivateencryptedkey && userData.documentprivateencryptedkey){
                    return resolve()
                }
                let jwtpublickey, jwtPrivateKey, documentpublickey, documentPrivateKey
                let jwtprivateencryptedkey, documentprivateencryptedkey
                if(this.#hasPermissionForSignDocumentKey(userData.role)){  
                    if(!userData.jwtprivateencryptedkey && !userData.documentprivateencryptedkey){
                        const [ jwtKeys, documentKeys ] = await Promise.all([this.#RSAGenerateKeyPair(), this.#RSAGenerateKeyPair()]);
                        [ jwtpublickey, jwtPrivateKey ] = jwtKeys;
                        [ documentpublickey, documentPrivateKey ] = documentKeys;

                    }else if(!userData.jwtprivateencryptedkey){
                        [ jwtpublickey, jwtPrivateKey ] = await this.#RSAGenerateKeyPair()
                    }
        
            
                    jwtprivateencryptedkey = await this.AES256encrypt(jwtPrivateKey, userId)
                    documentprivateencryptedkey = await this.AES256encrypt(documentPrivateKey, userId)
                    
                }else{
                    if(!userData.jwtprivateencryptedkey){
                        [ jwtpublickey, jwtPrivateKey ] = await this.#RSAGenerateKeyPair()
                        jwtprivateencryptedkey = await this.AES256encrypt(jwtPrivateKey, userId)
                    }
                }       
                await this.#storeKeysInDatabase(userId, jwtpublickey, jwtprivateencryptedkey, documentpublickey, documentprivateencryptedkey)
                resolve()
            } catch (error) {
                reject(statusAndError(error))
            }

        })
    }

    async #storeSignedDocument(userId, type, applicant, publicKey, signature, documentId, bucketref, manager){

        const payload = {
            bucketref,
        }
        // Update RDA
        if( type.toLowerCase() === "rda"){
            if(userId === applicant){ // First sign
                console.log("first sign");
                payload.applicantsignature=signature,
                payload.applicantpublickey=publicKey
                await updateDocApplicantOrManagerSignature(documentId, payload, applicant)
                
            } else if(userId === manager){ // Second sign
                console.log("second sign");
                payload.managersignature=signature,
                payload.managerpublickey=publicKey
                await updateDocApplicantOrManagerSignature(documentId, payload, manager, true)
            }
        }
        
        // Once both have signed we will have 4 fields representing type, flow, publicKey, signature
    }

    async #signOrVerifyDocumentHash({type, flow, applicant, dataToVerify, documentID, manager}){
        return new Promise(async(resolve, reject) => {
            try {
                if(flow === this.RSAsignDocument.name){
                    const {privateEncyptedKey, publicKey } = await getUserById(applicant)
                    const privateKey = await this.AES256decrypt(privateEncyptedKey, applicant)
                    const sign = createSign('SHA256');
                    sign.update(dataToVerify);
                    sign.end();
                    const signature = sign.sign(privateKey, 'hex');
                    if(type.toLowerCase() === "rda") {
                        
                    }
                    return await this.#storeSignedDocument(type, applicant, publicKey, signature, documentID, manager )
                }else if(flow === this.RSAverifySignature.name){
                    let applicant, signature;
                    if(type.toLowerCase() === "rda"){
                        ({ applicant, signature } = "manager && documentID") // DB get RDA with manager == manager and rdaId = rdaId
                    }    
                    if(!applicant || !signature) throw "RSAverifySignature -- !applicant || !signature err -- not a valid type"
                    const {  publicKey } = await getUserById(applicant) // DB(USER: based on applicant) 
                    const verify = createVerify('SHA256');
                    verify.update(dataToVerify);
                    verify.end();
                    resolve(verify.verify(publicKey, signature, 'hex'))
                }
            } catch (error) {
                reject({flow,status:500,message:error?.message??JSON.stringify(error)})
            }

        })
    }

    // Method to sign documents, for both, applicant and manager:
    /**
        @params
            userId: id of the signer
            type: documentType ( RDA, .... )
            dataToVerify: documentHash ( sha256 )
            applicant: applicant Id
            documentID: doc id
            bucketRef: url where the doc is stored
            manager: manager id
    */
    async RSAsignDocument(userId, type, { dataToVerify, applicant, documentId, bucketRef, manager }){
        return new Promise(async(resolve,reject) => {
            try {

                if(userId !== applicant && userId !== manager)
                    return reject({message:"Not allowed", status:403})
                // Get signer RSA keys
                const { documentprivateencryptedkey, documentpublickey:publicKey } = await getUserById(userId)
                const privateKey = await this.AES256decrypt(documentprivateencryptedkey.toString('utf-8'), userId)
                const sign = createSign('SHA256');
                sign.update(dataToVerify);
                sign.end();
                const signature = sign.sign(privateKey, 'hex');                
                const isStored = await this.#storeSignedDocument(userId, type, applicant, publicKey, signature, documentId, bucketRef, manager )

                resolve(isStored)
            } catch (error) {
                reject(error)
            }
        })

    }
    
    // Method to verify data
    async RSAverifySignature(type, dataToVerify, manager, documentID){
        // Must be able to verify both the first and second signature:
        // If only the first is in the DB, verify that one, otherwise the other
        
        // Get public key of the user who generated the document   
        // Get signature as well       
        // Get the RDA, so I can have the applicant's id and the signature
        // With the manager's id, get the applicant's public key, which is found in RDA
        return await this.#signOrVerifyDocumentHash(
                    {
                        type,
                        documentID,
                        manager,
                        dataToVerify,
                        flow: this.RSAverifySignature.name,manager
                    }
                )
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

const Cipher = new CipherSingleton()
export default Cipher
