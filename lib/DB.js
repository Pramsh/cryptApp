import { dbHashedFields } from '../utils/constants.js'
import { statusAndError, cLog } from '../utils/functions.js'
import pg from 'pg'
const { Pool } = pg
// export default class DB{

//     static instance 

let pool
pool = pool ? pool : 
    new Pool({
        host: "localhost",
        user: "root",
        port: 5432,
        database: "User", 
        password: "root",
        max: 50, // Maximum number of clients in the pool
        idleTimeoutMillis: 5000, // Close clients after 5 seconds of inactivity
    })
    
    
   

    // })}
    
// }
// const pool = await InitDB()
// Function to create a hash index on the encrypted_key column

export async function setupDB() {
    const client = await pool.connect();
    try {
        await client.query('BEGIN')
        await client.query('CREATE EXTENSION IF NOT EXISTS "pgcrypto"; -- Make sure to enable the pgcrypto extension to use gen_random_uuid()')
        
        await client.query(`
           CREATE TABLE users (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(), -- Use UUID instead of SERIAL
            firstName VARCHAR(50) NOT NULL,
            lastName VARCHAR(50) NOT NULL,
            username VARCHAR(50) NOT NULL,
            email VARCHAR(50) UNIQUE NOT NULL,
            role VARCHAR(10) NOT NULL,
            jwtpublickey TEXT UNIQUE, -- in fase di creazione dell'utente non ci sarà
            jwtprivateencryptedkey TEXT UNIQUE,
            documentpublickey TEXT UNIQUE,
            documentprivateencryptedkey BYTEA UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
           );
        `);


        await client.query('COMMIT');




        await client.query('BEGIN')

        await client.query(`
            CREATE TABLE rda (
             id UUID PRIMARY KEY DEFAULT gen_random_uuid(), -- Use UUID instead of SERIAL
             documentsha VARCHAR(64),
             applicant UUID NOT NULL,
             applicantsignature BYTEA,
             applicantpublickey TEXT,
             manager UUID NOT NULL,
             managersignature BYTEA,
             managerpublickey TEXT,
             bucketref VARCHAR(50),
             created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
             CONSTRAINT fk_applicant FOREIGN KEY(applicant) REFERENCES users(id),
             CONSTRAINT fk_manager FOREIGN KEY(manager) REFERENCES users(id)
            );
         `);
       
         await client.query('COMMIT');


    } catch (error) {
        await client.query('ROLLBACK'); 
        console.error("Error creating table:", error);
    } finally {
        client.release();
    }
}


export async function createIndex() {
    const client = await pool.connect();
    try {
        await client.query('BEGIN'); 

        await client.query(`
            ALTER TABLE users DROP CONSTRAINT users_documentprivateencryptedkey_key;
        `);

        await client.query(`
            ALTER TABLE users DROP CONSTRAINT users_jwtprivateencryptedkey_key;
        `);

        await client.query(`
            CREATE INDEX IF NOT EXISTS users_documentprivateencryptedkey_key ON public.users USING HASH (documentprivateencryptedkey);
        `);
        await client.query(`
            CREATE INDEX IF NOT EXISTS users_jwtprivateencryptedkey_key ON public.users USING HASH (jwtprivateencryptedkey);
        `);


        console.log("Hash index created and inserted users.");
        await client.query('COMMIT'); 
    } catch (error) {
        console.error("Error creating index:", error);
        await client.query('ROLLBACK'); 
    } finally {
        client.release();
    }
}

export async function addTestData() {
    const client = await pool.connect();
    try {
        await client.query('BEGIN'); 
        await client.query(`
            INSERT INTO users (firstName, lastName, username, email, role)
             VALUES
             ('Alice', 'Smith', 'alice.smith', 'alice@example.com', 'user'),
             ('Bob', 'Johnson', 'bob.johnson', 'bob@example.com', 'admin'),
             ('Charlie', 'Brown', 'charlie.brown', 'charlie@example.com', 'user'),
             ('David', 'Williams', 'david.williams', 'david@example.com', 'user'),
             ('Eve', 'Davis', 'eve.davis', 'eve@example.com', 'user'),
             ('Frank', 'Garcia', 'frank.garcia', 'frank@example.com', 'admin'),
             ('Grace', 'Martinez', 'grace.martinez', 'grace@example.com', 'user'),
             ('Hank', 'Rodriguez', 'hank.rodriguez', 'hank@example.com', 'user'),
             ('Ivy', 'Hernandez', 'ivy.hernandez', 'ivy@example.com', 'user'),
             ('Jack', 'Lopez', 'jack.lopez', 'jack@example.com', 'user'),
             ('Jack', 'Young', 'jack.young', 'jack.young@example.com', 'user'),
            ('Aaron', 'Johnson', 'aaron.johnson', 'aaron.johnson@example.com', 'user'),
            ('Henry', 'Green', 'henry.green', 'henry.green@example.com', 'admin'),
            ('Cody', 'Cook', 'cody.cook', 'cody.cook@example.com', 'admin'),
            ('Bella', 'Smith', 'bella.smith', 'bella.smith@example.com', 'admin'),
            ('Sophia', 'Brown', 'sophia.brown', 'sophia.brown@example.com', 'admin'),
            ('Bob', 'Smith', 'bob.smith', 'bob.smith@example.com', 'admin'),
            ('Zane', 'Lopez', 'zane.lopez', 'zane.lopez@example.com', 'user'),
            ('Sophia', 'Edwards', 'sophia.edwards', 'sophia.edwards@example.com', 'admin'),
            ('Liam', 'Evans', 'liam.evans', 'liam.evans@example.com', 'user'),
            ('Yara', 'Hill', 'yara.hill', 'yara.hill@example.com', 'admin'),
            ('Charlie', 'Wright', 'charlie.wright', 'charlie.wright@example.com', 'admin'),
            ('Nate', 'Hall', 'nate.hall', 'nate.hall@example.com', 'user'),
            ('Grace', 'Baker', 'grace.baker', 'grace.baker@example.com', 'admin'),
            ('Lucas', 'Walker', 'lucas.walker', 'lucas.walker@example.com', 'user'),
            ('Xander', 'Davis', 'xander.davis', 'xander.davis@example.com', 'user'),
            ('Liam', 'Howard', 'liam.howard', 'liam.howard@example.com', 'user'),
            ('Xander', 'Evans', 'xander.evans', 'xander.evans@example.com', 'user'),
            ('Uma', 'Perez', 'uma.perez', 'uma.perez@example.com', 'admin'),
            ('Molly', 'Davis', 'molly.davis', 'molly.davis@example.com', 'admin'),
            ('Frank', 'Campbell', 'frank.campbell', 'frank.campbell@example.com', 'admin'),
            ('Vera', 'King', 'vera.king', 'vera.king@example.com', 'user'),
            ('Grace', 'Young', 'grace.young', 'grace.young@example.com', 'admin'),
            ('Jack', 'Edwards', 'jack.edwards', 'jack.edwards@example.com', 'user'),
            ('Elena', 'Brown', 'elena.brown', 'elena.brown@example.com', 'admin'),
            ('Walt', 'Young', 'walt.young', 'walt.young@example.com', 'admin'),
            ('Zane', 'Cook', 'zane.cook', 'zane.cook@example.com', 'admin'),
            ('Paul', 'Perez', 'paul.perez', 'paul.perez@example.com', 'user'),
            ('Elena', 'Martinez', 'elena.martinez', 'elena.martinez@example.com', 'user'),
            ('Sophia', 'Hughes', 'sophia.hughes', 'sophia.hughes@example.com', 'admin'),
            ('Ryan', 'Howard', 'ryan.howard', 'ryan.howard@example.com', 'admin'),
            ('Molly', 'Scott', 'molly.scott', 'molly.scott@example.com', 'user'),
            ('Oscar', 'Rogers', 'oscar.rogers', 'oscar.rogers@example.com', 'admin'),
            ('Alice', 'Evans', 'alice.evans', 'alice.evans@example.com', 'admin'),
            ('Henry', 'Wright', 'henry.wright', 'henry.wright@example.com', 'admin'),
            ('Aaron', 'Smith', 'aaron.smith', 'aaron.smith@example.com', 'admin'),
            ('Lucas', 'Johnson', 'lucas.johnson', 'lucas.johnson@example.com', 'user');
         `);
        await client.query('COMMIT'); 
        cLog("Test data added")
        
    } catch (error) {
        console.error("Error creating index:", error);
        await client.query('ROLLBACK'); 
    } finally {
        client.release();
    }
}

 
export const getUsers = async() => {
    const client = await pool.connect()
    return new Promise((resolve, reject) => {
        client.query("select id, role, documentpublickey, jwtpublickey from users", (err, res) => {
            if(!err){                
                resolve(res.rows)
            }else{
                reject({status:500, message:err.message})
            }
       return client.release()
        })
    })
}

export const getUserById = async(id) => {
    const client = await pool.connect()
    return new Promise((resolve, reject) => {
        client.query("select * from users WHERE id = $1", [id], (err, res) => {
            if(!err){   
                resolve(res.rows[0])
            }
            else{                
                reject({status:404, message:err.message})
            } 
        return client.release()
    })
})}

export const updateUserById = async(id, userData) => {
    return new Promise(async(resolve, reject) => {
        const client = await pool.connect()
        try {     
            const fieldsWithValue = Object.keys(userData).filter(field => userData[field] && userData[field] !== "undefined" && userData[field].trim() != "")
            const [sets, params ] = fieldsWithValue.reduce((prev, f,i) => {
                prev[0].push(`${f} = ($${i + 2})`);
                prev[1].push(dbHashedFields.some(field => field === f) ? Buffer.from(userData[f], "utf-8") : userData[f]) 
                return [prev[0], prev[1]]
            }, [[],[]])
                        
            const res = await client.query(`UPDATE users SET ${sets.join(", ")} WHERE id = $1`, [id, ...params])//, (err, res) => {//${sets.join(" ")}
            cLog("Correctly updated user with id " + id)
            resolve(res.rowCount)
        } catch (error) {
            reject(statusAndError(error))
        } finally {
            client.release()
        }
    })
}


export const createRDA = async(applicant,manager) => {
    return new Promise(async(resolve, reject) => {
        const client = await pool.connect()
        try {
            const res = await client.query(`
                INSERT INTO rda (applicant, manager)
                    VALUES ($1, $2) RETURNING id;
                `, [applicant, manager])
            resolve(res.rows[0].id)
        } catch (error) {
            reject(statusAndError(error))
        }finally {
            client.release()
        }
    })
}


export const updateDocApplicantOrManagerSignature = async (id, payload, managerOrApplicantId, isManager = false) => {
    const client = await pool.connect();
    try {     
        // Generate the params array, with hashing applied to certain fields
        const params = Object.keys(payload).map(field => 
            dbHashedFields.some(f => f === field) ? Buffer.from(payload[field], "utf-8") : payload[field]
        );

        // Choose the appropriate query based on whether the user is a manager or applicant
        const where = isManager ?
            " WHERE id = $1 AND manager = $2 AND applicantsignature is not null" :
            " WHERE id = $1 AND applicant = $2"
        let queryStr = isManager ? 
            `UPDATE rda 
             SET bucketref = $3, managersignature = $4, managerpublickey = $5, documentsha = $6` :
            `UPDATE rda 
             SET bucketref = $3, applicantsignature = $4, applicantpublickey = $5, documentsha = $6`;

        queryStr += where     

        // Execute the query
        const res = await client.query(queryStr, [id, managerOrApplicantId, ...params]);

        // Log success
        cLog("Correctly stored applicant/manager signature for RDA with id " + id);

        // Resolve the row count (number of updated rows)
        if(res.rowCount === 0){
            throw {
                message:"No RDA assigned according to the payload "+JSON.stringify(payload),
                status:401
            }
        }
        return res.rowCount
    } catch (error) {
        // Log and reject the error
        cLog(error?.message ?? error, "error");
        throw statusAndError(error)
    } finally {
        // Ensure the client is released back to the pool
        client.release();
    }
};


export const getRdaById = async(id) => {
    return new Promise(async(resolve, reject) => {
        const client = await pool.connect()
        try {                            
            const res = await client.query(`SELECT applicant, manager, documentsha, applicantsignature, applicantpublickey, managersignature, managerpublickey FROM rda WHERE id = $1`, [id]);
            
            
            if(res.rows.length === 0){
                return reject({message: "No RDA found with id " + id, status: 404})
            }
            
             // Parse hashed fields
            const parsedData = Object.keys(res.rows[0]).reduce((prev, field) => {
                prev[field] = dbHashedFields.some(f => f === field) && res.rows[0]?.field ? Buffer.from(res.rows[0]?.[field]).toString('utf-8') : res.rows[0][field];
                return prev
            },{});
            
            resolve(parsedData)
        } catch (error) {
            cLog(error?.message ?? error, "error")
            reject(statusAndError(error))
        } finally {
            client.release()
        }
    })
}

export const getRdaWithNullSignatures = async () => {
    const client = await pool.connect();
    return new Promise((resolve, reject) => {
        client.query(
            "SELECT * FROM rda WHERE applicantsignature IS NULL AND managersignature IS NULL",
            (err, res) => {
                if (!err) {
                    resolve(res.rows);
                } else {
                    reject({ status: 500, message: err.message });
                }
                client.release();
            }
        );
    });
};


export const getDocument = async(type, id) => {
    if(type.toLowerCase() === "rda"){
        return getRdaById(id)
    }
}
// export const getRDAbyApplicantOrManager = async(applicant, id, managerOrApplicant = "applicant") => {
//     const client = await pool.connect()
//     return new Promise((resolve, reject) => {
//         client.query(`select id from users WHERE ${managerOrApplicant} = $1 AND id = $2`, [applicant, id], (err, res) => {
//             if(!err)
//                 resolve(res.rows[0])
//             else reject(statusAndError(err))
//         return client.release()
//     })
// })}