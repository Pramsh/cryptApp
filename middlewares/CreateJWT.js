import { getClientIP, checkVariables, JWTexpirationTime } from "../utils/functions.js"
import { getUserById } from "../lib/DB.js";
export default async function CreateJWT(req, res, next){
    try {
        const user = req.body
        let { email, role, jwtprivateencryptedkey, id, token_version=1, ip } = user;
        
        if(!email || !role || !jwtprivateencryptedkey){
            ({ email, role, jwtprivateencryptedkey } = await getUserById(id))
        } 

        await checkVariables({token_version: token_version, id, email, role, jwtprivateencryptedkey })
        
        const payload = {
            id,
            email,
            role,
            ip: ip || getClientIP(req),
            token_version: token_version,
            exp: JWTexpirationTime(), // Expiration 1h
        };
        
        // Decrypt key                
        const jwtPrivateKey = await Cipher.AES256decrypt(jwtprivateencryptedkey.toString("utf-8"), id)
        const sign = await Cipher.createJWT(payload, jwtPrivateKey)
        res.status(200).send(sign)
    } catch (error) {    
        res.status(error?.status ?? 500).send(error?.message ?? JSON.stringify(error))
    }
}
