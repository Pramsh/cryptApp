export const userPermissions = ["admin", "user"]

export const signDocumentsPermissions = ["admin"]

export const JWTexpirationTimeValue = 60 * 15 //15min
//After 15min of session user has 15 min to refresh token
//for a max of 30 times
export const maxRefreshToken = 30 //maxSession (about JWTexpirationTimeValue*2) *  maxRefreshToken s

export const IPheader = 'x-forwarded-for'

export const dbHashedFields = ["jwtprivateencryptedkey","documentpublickey", "applicantsignature", "managersignature"]

//client rules
export const clientForbiddenFields = ["jwtPrivateKey"]


//query params sets
export const signDocumentsParams = Object.freeze(["applicant", "manager", "documentsha"])
export const verifyDocumentParams = Object.freeze(["applicant", "manager","applicantsignature", "documentsha"])