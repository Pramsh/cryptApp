import { createCipheriv, createDecipheriv, pbkdf2Sync, generateKeyPair, createVerify, createSign, createHash, constants, sign, verify } from 'crypto';
import * as dotenv from 'dotenv';
import { signDocumentsPermissions } from '../utils/constants.js';
import { isValidJSON, statusAndError } from '../utils/functions.js';
import { updateUserById } from './DB.js';

dotenv.config();

/**
 * @class CipherSingleton
 * @description Singleton class providing cryptographic functionalities.
 */
class CipherSingleton {
    static instance;
    #aes256Key;
    #aes256Iv;
    #appKey;
    #appToken;

    /**
     * @constructor
     */
    constructor() {
        if (CipherSingleton.instance) return CipherSingleton.instance;

        this.#aes256Key = process.env.KEY;
        this.#aes256Iv = process.env.IV;
        this.#appKey = this.#sha256(process.env.APP_KEY);
        this.#appToken = this.#sha256(process.env.APP_TOKEN);
        CipherSingleton.instance = this;
    }

    /**
     * Generates a SHA-256 hash of the input.
     * @param {string} input - The input string to hash.
     * @returns {string} - The SHA-256 hash of the input.
     */
    #sha256(input) {
        const hash = createHash('sha256');
        hash.update(input);
        return hash.digest('hex');
    }

    /**
     * Checks client headers for validity.
     * @param {string} clientAppKey - The client app key.
     * @param {string} clientAppToken - The client app token.
     * @returns {Promise<boolean>} - Whether the headers are valid.
     */
    CheckClientHeaders(clientAppKey, clientAppToken) {
        return new Promise((resolve, reject) => {
            if (clientAppKey === this.#appKey && clientAppToken === this.#appToken) {
                resolve(true);
            } else {
                if (!process.env.APP_KEY || !process.env.APP_TOKEN) {
                    reject({
                        message: "Internal Server Error",
                        status: 500
                    });
                } else if (!clientAppKey || !clientAppToken) {
                    reject({
                        message: "Missing credentials",
                        status: 401
                    });
                } else {
                    reject({
                        message: "Wrong credentials",
                        status: 403
                    });
                }
            }
        });
    }

    /**
     * Generates an RSA key pair.
     * @returns {Promise<Array<string>>} - The generated RSA key pair [publicKey, privateKey].
     */
    async RSAGenerateKeyPair() {
        return new Promise((resolve, reject) => {
            generateKeyPair('rsa', {
                modulusLength: 2048, // Length of key in bits
                publicKeyEncoding: {
                    type: 'spki', // Recommended to use 'spki' for public key
                    format: 'pem', // Format for public key
                },
 privateKeyEncoding: {
                    type: 'pkcs8', // Recommended to use 'pkcs8' for private key
                    format: 'pem', // Format for private key
                }
            }, (err, publicKey, privateKey) => {
                if (err) {
                    return reject(err); // Reject the promise on error
                }
                resolve([publicKey, privateKey]); // Resolve with the keys
            });
        });
    }

    /**
     * Stores encrypted keys in the database.
     * @param {string} userId - The user ID.
     * @param {string} jwtpublickey - The JWT public key.
     * @param {string} jwtprivateencryptedkey - The encrypted JWT private key.
     * @param {string} documentpublickey - The document public key.
     * @param {string} documentprivateencryptedkey - The encrypted document private key.
     * @returns {Promise<string>} - The result of the operation.
     */
    async #storeKeysInDatabase(userId, jwtpublickey, jwtprivateencryptedkey, documentpublickey, documentprivateencryptedkey) {
        return new Promise(async (resolve, reject) => {
            try {
                let payload = undefined;
                if (jwtpublickey && documentpublickey) {
                    payload = {
                        jwtpublickey,
                        jwtprivateencryptedkey,
                        documentpublickey,
                        documentprivateencryptedkey
                    };
                } else if (jwtpublickey) {
                    payload = {
                        jwtpublickey,
                        jwtprivateencryptedkey
                    };
                } else if (documentpublickey) {
                    payload = {
                        documentpublickey,
                        documentprivateencryptedkey
                    };
                }

                if (payload) {
                    await updateUserById(userId, payload);
                }
                resolve("ok");
            } catch (error) {
                reject(error);
            }
        });
    }

    /**
     * Creates a JWT.
     * @param {Object} payload - The payload of the JWT.
     * @param {string} jwtPrivateKey - The private key to sign the JWT with.
     * @returns {Promise<string>} - The generated JWT.
     */
    async createJWT(payload, jwtPrivateKey) {
        return new Promise(async (resolve, reject) => {
            try {
                const header = JSON.stringify({ alg: 'RS256', typ: 'JWT' });
                const base64Header = Buffer.from(header).toString('base64url');
                const base64Payload = Buffer.from(JSON.stringify(payload)).toString('base64url');

                const signatureInput = `${base64Header}.${base64Payload}`;
                const signature = sign('RSA-SHA256', Buffer.from(signatureInput), {
                    key: jwtPrivateKey,
                    padding: constants.RSA_PKCS1_PSS_PADDING,
                });

                const base64Signature = signature.toString('base64url');
                resolve(`${signatureInput}.${base64Signature}`);
            } catch (error) {
                reject(statusAndError(error));
            }
        });
    }

    /**
     * Decodes a JWT.
     * @param {string} JWTtoken - The JWT to decode.
     * @returns {Promise<Array>} - The decoded payload, signature input, and signature.
     */
    async #decodeJWT(JWTtoken) {
        return new Promise((resolve, reject) => {
            try {
                const [header64, payload64, signature64] = JWTtoken.split('.');
                const signatureInput = `${header64}.${payload64}`;
                // Decode the header and payload
                const payload = JSON.parse(Buffer.from(payload64, 'base64url').toString());
                resolve([payload, signatureInput, signature64]);
            } catch (error) {
                reject({ status: 401, message: "Error decoding JWT -- " + error?.message ?? JSON.stringify(error) });
            }
        });
    }

    /**
     * Gets session data from a JWT.
     * @param {string} JWTtoken - The JWT to get session data from.
     * @returns {Promise<Object>} - The session data.
     */
    async getSessionData(JWTtoken) {
        return new Promise(async (resolve, reject) => {
            try {
                const [payload] = await this.#decodeJWT(JWTtoken);

                if (payload) {
                    resolve(payload);
                } else {
                    reject({ status: 401, message: "Invalid session" });
                }
            } catch (error) {
                reject({ status: error?.status ?? 500, message: "Error getting session -- " + (error?.message ?? JSON.stringify(error)) });
            }
        });
    }

    /**
     * Validates a JWT.
     * Called from client, returns always a token, if fails back to login.
     * @param {string} ip - The IP address of the client.
     * @param {string} jwt - The JWT to validate.
     * @param {string} jwtpublickey - The public key to validate the JWT with.
     * @returns {Promise<Object|boolean>} - The validated session data or false if invalid.
     */
    async validateJWT(ip, jwt, jwtpublickey) {
        return new Promise(async (resolve, reject) => {
            try {
                const [payload, signatureInput, signature64] = await this.#decodeJWT(jwt);

                if (payload.ip !== ip) {
                    return reject({ status: 401, message: "Changed IP" });
                }

                // Verify the signature
                const isValid = verify(
                    'RSA-SHA256',
                    Buffer.from(signatureInput), // Input made of headers and payloads
                    {
                        key: jwtpublickey,
                        padding: constants.RSA_PKCS1_PSS_PADDING,
                    },
                    Buffer.from(signature64, 'base64url') // Signature itself
                );

                resolve(isValid ? payload : false);
            } catch (error) {
                reject({ status: 500, message: "Error verifying token: " + (error?.message ?? error) });
            }
        });
    }

    /**
     * Signs data using RSA.
     * @param {string} privateKey - The private key to sign with.
     * @param {string} dataToVerify - The data to sign.
     * @param {string} [encoding='hex'] - The encoding of the signature.
     * @returns {Promise<string>} - The generated signature.
     */
    async RSAsignDocument(privateKey, dataToVerify, encoding = 'hex') {
        return new Promise(async (resolve, reject) => {
            try {
                const sign = createSign('SHA256');
                sign.update(dataToVerify);
                sign.end();
                const signature = sign.sign(privateKey, encoding);
                resolve(signature);
            } catch (error) {
                console.log(error);
                reject(error);
            }
        });
    }

    /**
     * Verifies an RSA signature.
     * @param {string} dataToVerify - The data to verify.
     * @param {string} publicKey - The public key to verify with.
     * @param {string} signature - The signature to verify.
     * @param {string} [encoding='hex'] - The encoding of the signature.
     * @returns {Promise<boolean>} - Whether the signature is valid.
     */
    async RSAverifySignature(dataToVerify, publicKey, signature, encoding='hex') {
        return new Promise((resolve, reject) => {
            try {
                // Convert signature from hex to buffer and then to UTF-8 string
                const signatureBuffer = Buffer.from(signature).toString('utf-8');
                console.log(signatureBuffer, "signatureBuffer");

                // Create a Verify object
                const verify = createVerify('SHA256');
                verify.update(dataToVerify);
                verify.end();

                // Verify the signature
                resolve(verify.verify(publicKey, signatureBuffer, encoding));
            } catch (error) {
                reject({ message: "Error verifying signature -- details: " + (error?.message ?? JSON.stringify(error)), status: 500 });
            }
        });
    }

    /**
     * Generates a key and IV for AES encryption.
     * @param {string} salt - The salt used for key derivation.
     * @returns {Array<Buffer>} - The derived key and IV.
     */
    #generateKeyAndIv(salt) {
        return [pbkdf2Sync(this.#aes256Key, salt, 100000, 32, 'sha512'), pbkdf2Sync(this.#aes256Iv, salt, 100000, 16, 'sha512')];
    }

    /**
     * Encrypts text using AES-256-CBC.
     * @param {string|Object} text - The text to encrypt.
     * @param {string} salt - The salt used for key derivation.
     * @returns {Promise<string>} - The encrypted text.
     */
    async AES256encrypt(text, salt) {
        return new Promise((resolve, reject) => {
            try {
                const [key, iv] = this.#generateKeyAndIv(salt);
                const cipher = createCipheriv('aes-256-cbc', key, iv);
                if (typeof text === "object") {
                    text = JSON.stringify(text);
                }
                resolve(cipher.update(text, 'utf-8', 'hex') + cipher.final('hex'));
            } catch (error) {
                reject({ message: "An error occurred while AES encrypting -- details: " + error?.message, status: 403 });
            }
        });
    }

    /**
     * Decrypts text using AES-256-CBC.
     * @param {string} cryptedText - The encrypted text to decrypt.
     * @param {string} salt - The salt used for key derivation.
     * @returns {Promise<string|Object>} - The decrypted text or JSON object.
     */
    async AES256decrypt(cryptedText, salt) {
        return new Promise((resolve, reject) => {
            try {
                const [key, iv] = this.#generateKeyAndIv(salt);
                const decipher = createDecipheriv('aes-256-cbc', key, iv);
                const decryptedValue = decipher.update(cryptedText, 'hex', 'utf8') + decipher.final('utf8');
                let stringifyIfNeeded = isValidJSON(decryptedValue) ? JSON.parse(decryptedValue) : decryptedValue;
                resolve(stringifyIfNeeded);
            } catch (error) {
                reject({ message: "Error trying to AES256decrypt -- details: " + error?.message ?? JSON.stringify(error), status: 500 });
            }
        });
    }
}

const Cipher = new CipherSingleton();
export default Cipher;