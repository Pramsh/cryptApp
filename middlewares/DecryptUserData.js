export default async function DecryptUserData(req, res, next){
    try {
        const { data : strToEncrypt, salt } = req.body             
        res.status(200).send(await Cipher.AES256decrypt(strToEncrypt, salt))
    } catch (error) {
        res.status(error?.status ?? 500).send(error?.message ?? "Internal Server Error")
    }
}