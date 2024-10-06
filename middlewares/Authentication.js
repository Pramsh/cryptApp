export default async function Authentication(req, res, next){
    try {
        const { appkey: appKey, apptoken: appToken } = req.headers            
        await Cipher.CheckClientHeaders(appKey, appToken)
        && next()
    } catch (error) {
        res.status(error.status ?? 500).send(error.message ?? error)
    }
}