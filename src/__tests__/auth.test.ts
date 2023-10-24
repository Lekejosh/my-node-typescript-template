import supertest from "supertest";
import { MongoMemoryServer } from "mongodb-memory-server";
import mongoose from "mongoose";
import User from "./../models/user.model";
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

    describe("get profile", () => {
        it("should return a 200 status code", async () => {
            const response = await supertest(app).get("/api/v1/user/me").set("Authorization", `Bearer ${accessToken}`).send();

            expect(response.status).toBe(200);
        });
    });
    describe("update profile", () => {
        it("should return a 200 status code", async () => {
            const response = await supertest(app).put("/api/v1/user/me").set("Authorization", `Bearer ${accessToken}`).send({ name: "Updated name" });
            expect(response.status).toBe(200);
        });
    });
    describe("update password", () => {
        it("should return a 400 status code", async () => {
            const response = await supertest(app).put("/api/v1/auth/password").set("Authorization", `Bearer ${accessToken}`).send({
                oldPassword: "Password1$",
                newPassword: "Password1$",
                confirmPassword: "Password1$"
            });
            expect(response.status).toBe(400);
        });
    });
    describe("get users -- admin", () => {
        it("should return a 200 status code", async () => {
            const response = await supertest(app).get("/api/v1/admin").set("Authorization", `Bearer ${accessToken}`);
            expect(response.status).toBe(200);
        });
    });
    describe("get one user -- admin", () => {
        it("should return a 200 status code", async () => {
            const response = await supertest(app).get(`/api/v1/admin/${userId}`).set("Authorization", `Bearer ${accessToken}`);
            expect(response.status).toBe(200);
        });
    });
    describe("update one user -- admin", () => {
        it("should return a 200 status code", async () => {
            const response = await supertest(app).put(`/api/v1/admin/${userId}`).set("Authorization", `Bearer ${accessToken}`).send({
                name: "test test"
            });
            expect(response.status).toBe(200);
        });
    });
    describe("delete one user -- admin", () => {
        it("should return a 200 status code", async () => {
            const response = await supertest(app).delete(`/api/v1/admin/${userId}`).set("Authorization", `Bearer ${accessToken}`);
            expect(response.status).toBe(200);
        });
    });
    describe("logout", () => {
        it("should return a 400 status code", async () => {
            const response = await supertest(app)
                .delete("/api/v1/auth/logout")
                .set("Cookie", [`refreshToken=${refreshToken}`]);
            expect(response.status).toBe(400);
        });
    });
});
