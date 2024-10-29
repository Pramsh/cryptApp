import { getUsers, getRdaWithNullSignatures, getUserById, getRdaById } from "../../lib/DB";
import CreateJWT from "../../middlewares/CreateJWT";
import { jwtMockRes, signMockRes } from "../utils/db_mock";
import SignDocument from "../../middlewares/SignDocument";

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

                // Check if there are RDAs with null signatures
                if (rdas.length === 0) {
                    console.error('No RDAs with null signatures found. Please delete users and RDA test tables and run the test endpoint to setup the DB again.');
                    throw new Error('RDA with null signatures DOES NOT exist');
                }

                expect(rdas.length).toBeGreaterThan(0);
                rdas.forEach(rda => {
                    expect(rda.applicantsignature).toBeNull();
                    expect(rda.managersignature).toBeNull();
                });

                // Applicant signature
                const rda = rdas[0];
                const user = await getUserById(rda.applicant);

                // Get JWT
                const JTWreq = {
                    body: user,
                    headers: {
                        'x-forwarded-for': '128.0.0.1'
                    }
                };
                await CreateJWT(JTWreq, jwtMockRes);

                // Sign document
                const signReq = {
                    body: {
                        JWTtoken: jwtMockRes.send.mock.calls[0][0],
                        docType: "RDA",
                        docData: {
                            dataToVerify: "316854f29074ee522c5120b9b9fbe45333a75774fefd5ef0759ccf3a74fb6ed2", // random sha256
                            bucketRef: "gcp-linksoooo",
                            docId: rda.id
                        },
                        docId: rda.id,
                    },
                    headers: {
                        'x-forwarded-for': '128.0.0.1'
                    }
                };
                await SignDocument(signReq, signMockRes);

                // Verify the response
                expect(signMockRes.status).toHaveBeenCalledWith(200);
                expect(signMockRes.send.mock.calls[0][0]).toBe(true);

                // Check if the RDA has been updated with the applicant's signature
                const updatedRda = await getRdaById(rda.id);
                expect(updatedRda.applicantsignature).not.toBeNull();
            });
        });
    });
});
