import { getUserById } from "../lib/DB.js";
import { getClientIP } from "../utils/functions.js";

export const getSession = async (jwt,ip) => {
    try {
        const { id: userId } = await Cipher.getSessionData(jwt);
        const user = await getUserById(userId);
        const isValid = await Cipher.validateJWT(ip,jwt, user.jwtpublickey);

        if (isValid && user) {
            return user;
        } else {
            throw { status: 401, message: "Invalid session" };
        }
    } catch (error) {
        throw error;
    }
};

export async function GetSessionMid(req, res, next) {
    try {
        const { jwt } = req.body;
        const session = await getSession(jwt,getClientIP(req));    
        res.status(200).send(session);
    } catch (error) {
        res.status(error?.status ?? 500).send({ message: "Error getting session -- " + (error?.message ?? JSON.stringify(error)) });
    }
}
