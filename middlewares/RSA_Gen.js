import { hasSignDocumentsPermissions } from "../utils/functions.js";
import { getUserById } from "../lib/DB.js";

const storeKeysInDatabase = (userId, jwtpublickey, jwtprivateencryptedkey, documentpublickey, documentprivateencryptedkey) => 
    new Promise(async(resolve, reject) => {
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





export default async function RSA_Gen(req, res, next){
    const { userId }= req.body
     try {      
        const userData = await getUserById(userId)
                
        // Skip if user already has both keys
        if( userData.jwtprivateencryptedkey && userData.documentprivateencryptedkey){
            return resolve()
        }
        let jwtpublickey, jwtPrivateKey, documentpublickey, documentPrivateKey
        let jwtprivateencryptedkey, documentprivateencryptedkey
        if(hasSignDocumentsPermissions(userData.role)){  
            if(!userData.jwtprivateencryptedkey && !userData.documentprivateencryptedkey){
                const [ jwtKeys, documentKeys ] = await Promise.all([Cipher.RSAGenerateKeyPair(), Cipher.RSAGenerateKeyPair()]);
                [ jwtpublickey, jwtPrivateKey ] = jwtKeys;
                [ documentpublickey, documentPrivateKey ] = documentKeys;

            }else if(!userData.jwtprivateencryptedkey){
                [ jwtpublickey, jwtPrivateKey ] = await Cipher.RSAGenerateKeyPair()
            }

            [ jwtprivateencryptedkey, documentprivateencryptedkey ] = await Promise.all([ 
                Cipher.AES256encrypt(jwtPrivateKey, userId),
                Cipher.AES256encrypt(documentPrivateKey, userId)
            ])
            
        }else{
            if(!userData.jwtprivateencryptedkey){
                [ jwtpublickey, jwtPrivateKey ] = await Cipher.RSAGenerateKeyPair()
                jwtprivateencryptedkey = await Cipher.AES256encrypt(jwtPrivateKey, userId)
            }
        }       

        await storeKeysInDatabase(userId, jwtpublickey, jwtprivateencryptedkey, documentpublickey, documentprivateencryptedkey)
        res.status(200).send("ok")
     } catch (error) {       
         res.status(error?.status ?? 500).send("Error generating RSA keys for userId "+userId+" -- details: "+error.message)
     }
}
