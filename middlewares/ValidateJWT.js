import { getClientIP } from "../utils/functions.js"

export default async function ValidateJWT(req, res, next){
    try {
        const { jwt } = req.body
        const refreshedJwt = await Cipher.validateJWT(getClientIP(req), jwt)
        res.status(200).send(refreshedJwt)
    } catch (error) {
        res.status(error?.status ?? 500).send(error?.message ?? JSON.stringify(error))
    }
}