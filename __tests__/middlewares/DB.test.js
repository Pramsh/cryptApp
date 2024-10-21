import { getUsers, getRdaWithNullSignatures, getUserById } from "../../lib/DB";

describe("DB", () => {
    describe("User", () => {
        
        describe('if users exist', () => {
            it("should return all ids", async () => {
                const ids = await getUsers();
                expect(ids).toBeInstanceOf(Array);
                expect(ids.length).toBeGreaterThan(0);
                ids.forEach(id => {
                    expect(typeof id).toBe('object');
                });
            });
        });   
        
    });


    describe("RDA", () => {
        describe('if RDA exist', () => {
            it("should return all ids", async () => {
                const ids = await getUsers();
                expect(ids).toBeInstanceOf(Array);
                expect(ids.length).toBeGreaterThan(0);
                ids.forEach(id => {
                    expect(typeof id).toBe('object');
                });
            });
        });

        describe('if RDA with null signatures exist', () => {
            it("should sign a RDA with applicant and manager sign = null", async () => {
                const rdas = await getRdaWithNullSignatures();
                expect(rdas).toBeInstanceOf(Array);
                rdas.forEach(rda => {
                    expect(rda.applicantsignature).toBeNull();
                    expect(rda.managersignature).toBeNull();
                });
                //applicant signature
                const rda = rdas[0]
                const user = await getUserById(rdas[0].applicant)
                //get JWT
                const JTWreq = {
                    body: user
                }
                const jwt = await CreateJWT(JTWreq, jwtMockRes)
                const signReq = {
                    body: {
                        JWTtoken: jwt,
                        docType: "RDA",
                        docData: {
                            dataToVerify: "316854f29074ee522c5120b9b9fbe45333a75774fefd5ef0759ccf3a74fb6ed2", //random sha256
                            bucketRef: "gcp-linksoooo",
                            docId: rda.id
                        }
                    }
                }
                const signedDoc = await SignDocument(signReq, signMockRes)
                expect(signedDoc).toBe(true);
                const updatedRda = await getRdaWithNullSignatures();
                
                expect(updatedRda[0].applicantsignature).not.toBeNull();
                
            });
        });
    });
});    

