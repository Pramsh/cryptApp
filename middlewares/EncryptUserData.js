export default async function EncryptUserData(req, res, next){
    try {
        const { data : strToEncrypt, salt  } = req.body 
        const result = await Cipher.AES256encrypt(strToEncrypt, salt)        
        res.status(200).send(result)
    } catch (error) {       
        res.status(error?.status ?? 500).send(error?.message ?? "Internal Server Error")
    }
}