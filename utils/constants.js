export const signDocumentsPermissions = ["admin"]

export const JWTexpirationTimeValue = 60 * 60 //1h
//After 1h of session user has 1 hour to refresh token
//for a max of 9 times
export const maxRefreshToken = 10 //maxSession (about JWTexpirationTimeValue*2) *  maxRefreshToken s

export const IPheader = 'x-forwarded-for'

export const dbHashedFields = ["jwtprivateencryptedkey","documentpublickey", "applicantsignature", "managersignature"]

