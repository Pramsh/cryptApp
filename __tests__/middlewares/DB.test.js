import { getUsers } from "../../lib/DB";

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
});