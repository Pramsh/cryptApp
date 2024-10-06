### Not finished yet

The purpose of this service is to isolate the cypher logic into a single serveer.


### Exposed endpoint

#### Encrypt
Usefull to send information to be *encrypted*.

Returns the aes256cbc encoded string of the input you've send within the **data** field of the body req.

POST - crypt-app/encrypt

body req:
```
{
    "data":"message-to-encrypt",
    "salt":"sha256 of userId for dynamic salt to generatate iv for aes256cbc encryption"
}
```


#### Decrypt
Usefull to send information to be *decrypted*.

Returns the aes256cbc decoded string of the input you've send within the **data** field of the body req. Since the IV is dynamic, to retrieve the specific message is necessary provide the same email salt as the person that encoded.

POST - crypt-app/decrypt

body req:
```
{
    "data":"message-to-decript",
    "salt":"sha256 of userId for dynamic salt to generatate iv for aes256cbc decryption"
}
```


### Sign documents
The data to be signed is first processed through a cryptographic hash function (i.e., SHA-256). This generates a fixed-size hash value (digest) that represents the original data.

##### Encrypting the Hash:
The hash is encrypted with the sender's private key using an asymmetric encryption algorithm (e.g., RSA). This encrypted hash is the digital signature.

##### Result:
The signature will be stored along with the original data document url.



#### validation
To validate it's necessary to retrieve the original document, based on rdaId and the reciverId


#### Endpoint to generete RSA keys for doc signatures
When a user with the right permission is added to the db, RSA keys must be added for doc validations.
These keys are saved onto the DB associated with the user's ID. Private key is AES256 encrypted




#### Endpoint to sign data
This endpoint is usefull to combine document's hash with the private key of the user.


##### Postgres testing setup

create docker volumee mount, run docker container montinung data on the volume. Map on ports 5432:5432.
Open a bash terminal on the docker instance and connect to db



#### JWT VALIDATION

* Token Validation: The input JWT is returned as long as it is valid. When expired, a new JWT token is generated and returned each time until it expires a second time.

* Token Versioning: Each newly generated (AND USED) JWT will have an incremented token_version. When the max n of token_version is reached a new Login is required.

* Token life: The maximum time per token is given by ```maxTimePerToken = (expirationTime * 2) - 0.001s```

* The total maximum session duration is given by ```maxTimePerSession = maxTimePerToken * max token_version```, after this time a new login is required.
