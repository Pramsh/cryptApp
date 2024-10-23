import express from 'express'
import Cipher from './lib/Cipher.js'
import * as dotenv from 'dotenv'
import Authentication from './middlewares/Authentication.js'
import EncryptUserData from './middlewares/EncryptUserData.js'
import DecryptUserData from './middlewares/DecryptUserData.js'
import CreateJWT from './middlewares/CreateJWT.js'
// import {getUsers} from './lib/DB.js'
import RSA_Gen from './middlewares/RSA_Gen.js'
import Test from './middlewares/Tes.js'
import ValidateJWT from './middlewares/ValidateJWT.js'
import Authenticate from './middlewares/Authenticate.js'
import SignDocument from './middlewares/SignDocument.js'
import { GetSessionMid } from './middlewares/GetSession.js'
import VerifySignature from './middlewares/VerifySignature.js'
//in partica gli altri server be saranno collegati a questo e passarenno gli header che verrann ocontrollati
//se non vanno l'app schianta
//quindi devo esporre un endpoint che valida solo gli header
dotenv.config()

const port = process.env.PORT || 5000
const app = express()

const router = express.Router();
app.use(express.json());

global.Cipher = Cipher;

app.use("/crypt-app", router)
//auth endpoint exposed for other servers
router.get('/headers-valid', Authenticate)

app.all('*', Authentication)

router.get("/test", Test)

router.post("/get-session", GetSessionMid)

router.post("/encrypt", EncryptUserData)

router.post("/decrypt", DecryptUserData)

router.post("/jwt", CreateJWT)

router.post("/jwt/validate", ValidateJWT)

router.post("/rsa-gen", RSA_Gen)

router.post("/sign-doc", SignDocument)

router.post("/verify-doc", VerifySignature)


app.listen(port, () => {
    console.log(`App listening on port ${port}`);
})