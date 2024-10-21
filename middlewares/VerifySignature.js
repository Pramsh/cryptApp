import { getRdaById } from "../lib/DB.js";
import { getClientIP } from "../utils/functions.js"
export default async function VerifySignature(req, res, next){
    try {
        const {
            JWTtoken,
            docId:id,
            docType,
            dataToVerify
        } = req.body
        
        let applicant, signature;
        if(docType.toLowerCase() === "rda"){
            ([{ applicant, signature }, [ userPayload ]] = await Promise.all([getRdaById(id), Cypher.getSessionInfo(getClientIP(req), JWTtoken)])); 
        }else{
            throw new Error("VerifySignature -- Invalid docType")
        }
        if(userPayload.id !== applicant || userPayload.id !== signature) throw new Error("RSAverifySignature -- Unauthorized")
        const {  publicKey } = await getUserById(userPayload.id) // DB(USER: based on applicant)     
        const isVerified = await Cipher.RSAverifySignature(dataToVerify, publicKey, signature)
        res.status(200).send(isVerified)
    } catch (error) {
        res.status(error?.status ?? 500).send(error.message ?? error)
    }
}