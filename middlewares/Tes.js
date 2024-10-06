import { addTestData, createIndex, createRDA, getUserById, getUsersIds, setupDB } from "../lib/DB.js";
import { divideChunks } from "../utils/functions.js";
export default async function Test(req, res, next){
    try {
        await setupDB()
        await createIndex()
        await addTestData()


        //crea le chiavi per tutti gli utenti
        const ids = await getUsersIds()
        const chunks = divideChunks(ids,10)
//dati 10 utenti posso creare 5 rda, 

        for(let el of chunks){
            await Promise.all(el.map(({id}) => Cipher.RSAhandleGeneration(id))).catch((E) =>{ console.log(E,"NOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO")}
            )
        }

        for(let el of chunks){
            for(let i = 0;i < el.length-2; i+=2){
                console.log(el[i+1].id , el[i].id, " INFO");
                const [{id:applicant}, {id:manager} ] = await Promise.all([getUserById(el[i].id), getUserById(el[i+1].id)])
                 await createRDA(applicant, manager).then(() => {console.log("rda ok")}
                 )
        }

            
        }



        res.status(200).send("ok")
    } catch (error) {
        console.log(error);
        
        res.status(500).send("ko")
        
    }
}