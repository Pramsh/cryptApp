const { getUsersIds } = require("../../lib/DB")

describe("DB", () => {
    describe("User", () => {
        
        describe('if users exists', () => {
            it("should return all ids", async () => {
                const ids = await getUsersIds();
                console.log(ids,"IDS");
                
            
            });
        });        
    });
});