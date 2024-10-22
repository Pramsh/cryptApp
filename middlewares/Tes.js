import { addTestData, createIndex, createRDA, getUserById, getUsers, setupDB } from "../lib/DB.js";
import { divideChunks } from "../utils/functions.js";
export default async function Test(req, res, next){
    try {
        await setupDB()
        await createIndex()
        await addTestData()

         //crea le chiavi per tutti gli utenti
         const ids = await getUsers()
         const chunks = divideChunks(ids,10)
 //dati 10 utenti posso creare 5 rda, 
 
         for(let el of chunks){
             await Promise.all(el.map(({id}) => {
                return fetch("http://localhost:5000/crypt-app/rsa-gen", {
                    headers: {
                        ...req.headers,
                        'Content-Type': 'application/json'
                    },
                    method: "POST",
                    body: JSON.stringify({ userId: id }),
                }).then((res) => {                    
                    return res.json()
                }).then(data => data)
            })).catch((E) => { 
                console.log(E, "NOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO")
            })
         }
 

         

         for(let el of chunks){
             for(let i = 0;i < el.length-2; i+=2){
                if(el[i].role === "admin" && el[i+1].role === "admin"){
                    const [{id:applicant}, {id:manager} ] = await Promise.all([getUserById(el[i].id), getUserById(el[i+1].id)])
                     await createRDA(applicant, manager).then(() => {console.log("rda ok")}
                     )
                }
         }
         }
        res.status(200).send("ok")
    } catch (error) {
        console.log(error);
        
        res.status(500).send("ko")
        
    }
}