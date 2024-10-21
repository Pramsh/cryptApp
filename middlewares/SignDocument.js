import { getClientIP } from "../utils/functions.js"
import { getDocument, getUserById, updateDocApplicantOrManagerSignature } from "../lib/DB.js";
import { getSession } from "./GetSession.js";

const storeSignedDocument = async(userId, type, applicant, publicKey, dataToVerify, signature, documentId, bucketref, manager) => {

    const payload = {
        bucketref,
    }
    // Update RDA
    if( type.toLowerCase() === "rda"){
        if(userId === applicant){ // First sign
            console.log("first sign");
            payload.applicantsignature=signature
            payload.applicantpublickey=publicKey
            payload.documentsha=dataToVerify
            await updateDocApplicantOrManagerSignature(documentId, payload, applicant)
            
        } else if(userId === manager){ // Second sign
            console.log("second sign");
            payload.managersignature=signature
            payload.managerpublickey=publicKey
            payload.documentsha=dataToVerify
            await updateDocApplicantOrManagerSignature(documentId, payload, manager, true)
        }
    }
    
    // Once both have signed we will have 4 fields representing type, flow, publicKey, signature
}

export default async function SignDocument(req, res, next){
    try {
        const {
            JWTtoken,
            docType,
            docData:{
                dataToVerify,
                bucketRef,
                docId
            }
            //look the destructured params of the method below to undestand what arrives
        } = req.body

        const { id:userId } = await getSession(JWTtoken,getClientIP(req))
        const [
            { documentprivateencryptedkey, documentpublickey:publicKey },
            { applicant, manager,  documentsha }
        ] = await Promise.all([getUserById(userId), getDocument(docType, docId)])
        console.log(documentprivateencryptedkey, publicKey, applicant, manager, "DATA");

        // Check if the document has been altered
        if (documentsha && documentsha !== dataToVerify) 
            return res.status(400).send("Document altered.");

        // Check if the user is allowed to sign the document
        if((userId !== applicant && userId !== manager) | (!documentprivateencryptedkey | !documentprivateencryptedkey))
            return res.status(403).send("Not allowed.");

        // Get signer RSA keys
        const privateKey = await Cipher.AES256decrypt(documentprivateencryptedkey.toString('utf-8'), userId)
        const signature = await Cipher.RSAsignDocument(privateKey, dataToVerify)
        await storeSignedDocument(userId, docType, applicant, publicKey, dataToVerify, signature, docId, bucketRef, manager )
        res.status(200).send(true)
    } catch (error) {
        res.status(error?.status ?? 500).send(error.message ?? error)
    }
}