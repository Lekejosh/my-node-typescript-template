import { testAuth } from "./auth";
import { userTest } from "./user";

describe("Sequential Test", () => {
    testAuth();
    userTest();
});
