export default async function SignDocument(req, res, next){
    try {
        const {
            JWTtoken,
            docType,
            docData//look the destructured params of the method below to undestand what arrives
        } = req.body

        const { id:userId } = await getSessionInfo(req.headers,JWTtoken)
        await Cipher.RSAsignDocument(userId, docType, docData)
        res.status(200).send(true)
    } catch (error) {
        console.log(error);
        res.status(error?.status ?? 500).send(error.message ?? error)
    }
}