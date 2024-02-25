export interface JWTPayload {
    id: string;
    iat: number;
    exp: number;
    role: "user" | "admin";
}

export interface PaginationInput {
    limit?: number;
    next?: string;
}
