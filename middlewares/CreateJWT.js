import { getClientIP } from "../utils/functions.js"
export default async function CreateJWT(req, res, next){
    try {
        const user = req.body
        const sign = await Cipher.createJWT(getClientIP(req), 1, user)
        res.status(200).send(sign)
    } catch (error) {    
        res.status(error?.status ?? 500).send(error?.message ?? JSON.stringify(error))
    }
}
