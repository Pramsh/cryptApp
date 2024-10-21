import { getClientIP, timesExpired, JWTexpirationTime } from "../utils/functions.js"
import { getUserById } from "../lib/DB.js";
import { maxRefreshToken } from "../utils/constants.js";
import CreateJWT from "./CreateJWT.js";
import { getSession } from "./GetSession.js";

export default async function ValidateJWT(req, res, next){
    try {
        const { jwt } = req.body
        const ip = getClientIP(req)
        const session = await getSession(jwt,ip);
        console.log(session,"session");
        
        const currentUserId = session.id;
        const { jwtpublickey, jwtprivateencryptedkey, email, role } = await getUserById(currentUserId);
        // const refreshedJwt = await Cipher.validateJWT(getClientIP(req), jwt)
        const payload = await Cipher.validateJWT(ip, jwt, jwtpublickey);
        
        if (!payload) {
            return res.status(401).send("Invalid token signature.");
        }

        if (!payload.role) {
            return res.status(403).send("Required permissions.");
        }

        if (payload.token_version > maxRefreshToken) {
            return res.status(403).send("Token limit reached.");
        }

        if (payload.ip !== getClientIP(req)) {
            return res.status(401).send("Changed IP.");
        }

        const currentTime = Math.floor(Date.now() / 1000);
console.log(Math.sign(payload.exp - currentTime),timesExpired(payload.exp, currentTime),"payload",payload.exp- currentTime);

        // If expired more than 1 time
        if (Math.sign(payload.exp - currentTime) === -1 && timesExpired(payload.exp, currentTime) > 1) {
            return res.status(401).send("Invalid token.");
        }

        // If expired one time
        if (payload.exp < currentTime) {
            const newData = { email, role };
            const oldData = { email: payload.email, role: payload.role };

            // Check if old user data correspond to new
            if (JSON.stringify(newData) === JSON.stringify(oldData)) {
            // Generate new token and return it to the client
            const newPayload = {
                id: currentUserId,
                email,
                role,
                ip: getClientIP(req),
                token_version: payload.token_version + 1,
                jwtprivateencryptedkey,
                exp: JWTexpirationTime()
            };

            return CreateJWT({...req, body:newPayload}, res, next);
            } else {
                return res.status(401).send("Token has expired and user data has changed.");
            }
        }
        res.status(200).send(jwt)
    } catch (error) {
        res.status(error?.status ?? 500).send(error?.message ?? JSON.stringify(error))
    }
}