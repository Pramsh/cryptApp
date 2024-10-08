import { addTestData, createIndex, createRDA, getUserById, getUsers, setupDB } from "../lib/DB.js";
import { divideChunks } from "../utils/functions.js";
export default async function Test(req, res, next){
    try {
        await setupDB()
        await createIndex()
        await addTestData()

        
        res.status(200).send("ok")
    } catch (error) {
        console.log(error);
        
        res.status(500).send("ko")
        
    }
}