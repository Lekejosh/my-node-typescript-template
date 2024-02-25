export interface UserDataInput {
    name?: string;
    email?: string;
    password?: string;
    role?: "user" | "admin";
    gender?: string;
    dateOfBirth?: Date;
    termsOfServices?: boolean;
}

export interface UserCreateInput {
    name?: string;
    email?: string;
    password?: string;
    role?: "user" | "admin";
    gender?: string;
    dateOfBirth?: Date;
    termsOfServices?: boolean;
}

export interface UserUpdateInput {
    name?: string;
    image?: string;
}
