export default async function Authenticate(req, res, next){
    try {
        const { appkey: appKey, apptoken: appToken } = req.headers                   
        await Cipher.CheckClientHeaders(appKey, appToken)
        &&  (res.status(200).json({isValid:true}))
    } catch (error) {
        res.status(error?.status ?? 500).json({
            message:error.message ?? error,
            isValid:false,
        })
    }
}