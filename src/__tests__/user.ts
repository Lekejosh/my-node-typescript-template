import supertest from "supertest";
import { app } from "..";
import { accessToken, refreshToken, userId } from "./auth";

export const userTest = () => {
    describe("User Test", () => {
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
            it("should return a 204 status code", async () => {
                const response = await supertest(app).delete(`/api/v1/admin/${userId}`).set("Authorization", `Bearer ${accessToken}`);
                expect(response.status).toBe(204);
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
};
