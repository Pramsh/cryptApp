import { createCipheriv, createDecipheriv, pbkdf2Sync, generateKeyPair, createVerify, createSign, createHash, constants, sign, verify } from 'crypto'
import * as dotenv from 'dotenv'
import { JWTexpirationTimeValue, signDocumentsPermissions, maxRefreshToken, IPheader } from '../utils/constants.js';
import { JWTexpirationTime, isValidJSON, statusAndError } from '../utils/functions.js';
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
        // return it as a hexadecimal string
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
       
    // Method to store the encrypted keys in the database
    async #storeKeysInDatabase(userId, jwtpublickey, jwtprivateencryptedkey, documentpublickey, documentprivateencryptedkey){
        return new Promise(async(resolve, reject) => {
            try {
                console.log(`Storing keys for user ${userId}...`);

                const storedData = {
                    jwtpublickey,
                    jwtprivateencryptedkey,
                    documentpublickey,
                    documentprivateencryptedkey
                };
        
                await updateUserById(userId, storedData)
                resolve("ok")
            } catch (error) {
                reject(error)   
            }
        })
    }


    #hasPermissionForSignDocumentKey(permission){
        return signDocumentsPermissions.some((perm) => perm === permission)
    }


//called on login, after user has been created
    async createJWT(ip, token_version, {id, email, role, jwtprivateencryptedkey}) {
        return new Promise(async(resolve, reject ) => {
            try {

                if(!email || !role || !jwtprivateencryptedkey){
                    ({ email, role, jwtprivateencryptedkey } = await getUserById(id))
                } 
                console.log(ip,"IP");
                
                const payload = {
                    id,
                    email,
                    role,
                    ip,
                    token_version: token_version,
                    exp:JWTexpirationTime(),//expiration 1h
                };
                //decript key                
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
        // const header = JSON.parse(Buffer.from(header64, 'base64url').toString());
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


    //called from client, returns always a token, if fails back to login
    async validateJWT(ip,JWTtoken){
        return new Promise(async(resolve, reject) => {
            try {
                const [payload, signatureInput, signature64 ] = this.#decodeJWT(JWTtoken)//JSON.parse(Buffer.from(payload64, 'base64url').toString());
                const currentUserId = payload.id
                const { jwtpublickey, jwtprivateencryptedkey, email, role } = await getUserById(currentUserId)

                // Verify the signature
                const isValid = verify(
                    'RSA-SHA256',
                    Buffer.from(signatureInput),    //input made of headers and payloads
                    {       
                        key: jwtpublickey,
                        padding: constants.RSA_PKCS1_PSS_PADDING,
                    },
                    Buffer.from(signature64, 'base64url') //signature itself
                );
    console.log(payload);
    
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
                
//if expired more than 1 times  
                if (Math.sign(payload.exp -  currentTime) === -1 && this.#timesExpired(payload.exp, currentTime) > 1){
                    return reject({ status: 401, message: "Invalid token." });
                }
   
//if expired one time
                if (payload.exp < currentTime) {
                    console.log("Expired***********************************");
                  
                    const newData = { email, role }
                    const oldData = { email:payload.email, role:payload.role }
                    
                    console.log(JSON.stringify(newData) === JSON.stringify(oldData),"EQUAL");
                    
                //Check if old user data correspond to new    
                    if(JSON.stringify(newData) === JSON.stringify(oldData)){

                        //generate new token and return it to the client
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

    //il servizio di login chiama l'endpoint sotto, restituisce il JWT
    //viene chiamato solo se l'utente è nuovo(forse anche se a db sono cambiati i permessi.)
    //se ha cambiato i permessi deve solo generare le nuove chiavi, le vecchie devono rimanere uguali O SI FA BORDELLO
    async RSAhandleGeneration(userId){ 
        return new Promise(async(resolve, reject) => {
            try {
                const userData = await getUserById(userId)
                //skip if user has already both keys
                if( userData.jwtprivateencryptedkey && userData.documentprivateencryptedkey){
                    return resolve()
                }
                let jwtpublickey, jwtPrivateKey, documentpublickey, documentPrivateKey
                let jwtprivateencryptedkey, documentprivateencryptedkey
                if(this.#hasPermissionForSignDocumentKey(userData.role)){  
                    const [ jwtKeys, documentKeys ] = await Promise.all([this.#RSAGenerateKeyPair(), this.#RSAGenerateKeyPair()]);
        
                    [ jwtpublickey, jwtPrivateKey ] = jwtKeys;
                    [ documentpublickey, documentPrivateKey ] = documentKeys;
            
                    jwtprivateencryptedkey = await this.AES256encrypt(jwtPrivateKey, userId)
                    documentprivateencryptedkey = await this.AES256encrypt(documentPrivateKey, userId)
                    
                }else{
                    [ jwtpublickey, jwtPrivateKey ] = await this.#RSAGenerateKeyPair()
                    jwtprivateencryptedkey = await this.AES256encrypt(jwtPrivateKey, userId)
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
        //aggiorno RDA
        if( type.toLowerCase() === "rda"){
            if(userId === applicant){ //first sign
                console.log("first sign");
                payload.applicantsignature=signature,
                payload.applicantpublickey=publicKey
                await updateDocApplicantOrManagerSignature(documentId, payload, applicant)
                
                
                //update field applicantSign to the actual signature
            } else if(userId === manager){//second sign
                console.log("second sign");
                payload.managersignature=signature,
                payload.managerpublickey=publicKey
                await updateDocApplicantOrManagerSignature(documentId, payload, manager, true)
                

            }
            
        }
        
        //once both have signed we will have 4 fields rappresenting //type,flow, publicKey, signature
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
                        ({ applicant, signature } = "manager && documentID")//DB get RDA with manager == manager and rdaId = rdaId
                    }    
                    // return { applicant, signature }
                    if(!applicant || !signature) throw "RSAverifySignature -- !applicant || !signature err -- not a valid type"
                    const {  publicKey } = await getUserById(applicant)// A DB(USER: based on applicant) 
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

    async #getUserById(userId){
//get user from DB
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
                //mi passa il token, mi prendo l'id,
                // se corrisponde all'id dell'applicant o del manager faccio aprtire il lfusso
                const { documentprivateencryptedkey, documentpublickey:publicKey } = await getUserById(userId) //get signer rsa keys
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
        //deve essere in grado di verificare sia la prima che la seconda firma:
        //Se a DB c'è solo la prima devo verificare quella, altrimenti l'altra
        
            //get public key dell'utente che ha generato il documento   
            //get signature anche       
            //devo prendere la rda, cosi posso avere l'id del richiedente e la fignature
            //con l'id del manager, devo prendere la public key del richiedente, che trovo in RDA
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
                reject({message:"an error occurred while AES encrypting -- details: "+error?.message, status: 500})
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