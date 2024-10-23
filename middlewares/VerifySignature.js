import { getRdaById } from "../lib/DB.js";
export default async function VerifySignature(req, res, next){
    try {

        const {
            docId:id,
            docType,
            dataToVerify
        } = req.body

        let  applicantsignature, applicantpublickey, managersignature, managerpublickey 

        if(docType.toLowerCase() === "rda"){
            ;({ applicantsignature, applicantpublickey, managersignature, managerpublickey } = await getRdaById(id))
        }else{
            throw new Error("VerifySignature -- Invalid docType")
        }
        
        const [ sign1, sign2 ] = await Promise.all([Cipher.RSAverifySignature(dataToVerify, applicantpublickey, applicantsignature), Cipher.RSAverifySignature(dataToVerify, managerpublickey, managersignature)])
        
        res.status(200).send({applicant:sign1, manager:sign2})
    } catch (error) {
        res.status(error?.status ?? 500).send(error.message ?? error)
    }
}


//quando salvo il document ci deve essere un servizio di be che lo recupera e genera lo sha256