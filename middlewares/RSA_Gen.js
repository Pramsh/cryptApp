export default async function RSA_Gen(req, res, next){
    const { userId }= req.body
     try {      
        await Cipher.RSAhandleGeneration(userId)
        res.status(200).send("ok")
     } catch (error) {       
         res.status(error?.status ?? 500).send("Error generating RSA keys for userId "+userId+" -- details: "+error.message)
     }
}