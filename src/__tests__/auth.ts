import supertest from "supertest";
import User from "../models/user.model";
import { app } from "..";

export const authPayload = {
    name: "Test Test",
    email: "test@test.com",
    password: "Password1$",
    gender: "male",
    termsOfService: true,
    dateOfBirth: "2000-06-20",
    isVerified: true,
    role: "admin"
};

export const userDetails = {
    email: "test@test.com",
    password: "Password1$"
};

export let refreshToken: string;
export let accessToken: string;
export let userId: string;

export const testAuth = () => {
    describe("Auth test", () => {
        beforeAll(async () => {
            const checkUser = await User.findOne({ email: authPayload.email });
            if (!checkUser) await User.create(authPayload);
            const response = await supertest(app).post("/api/v1/auth/login").send(userDetails);

            const setCookieHeader = response.header["set-cookie"];

            const refreshTokenMatch = setCookieHeader[0].match(/refreshToken=([^;]+)/);

            if (refreshTokenMatch && refreshTokenMatch.length > 1) {
                refreshToken = refreshTokenMatch[1];
            } else {
                console.log("RefreshToken not found");
            }
            accessToken = response.body.data.accessToken;
            userId = response.body.data.user._id;
        }, 15000);

        describe("login user", () => {
            it("should return a 200 status code", () => {
                expect(accessToken).toBeDefined();
            });
        });
    });
};
