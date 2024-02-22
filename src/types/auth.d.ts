export interface VerificationOne {
    first_name: string;
    last_name: string;
    email: string;
    username: string;
    phone_number: number;
    password: string;
}


export interface LoginInput {
    username_or_email: string;
    password: string;
}

export interface GenerateTokenInput {
    userId: string;
    role: string;
    email: string;
    isVerified: boolean;
}

export interface RefreshTokenInput {
    refreshToken: string;
}

export interface LogoutInput {
    refreshToken: string;
}

export interface VerifyEmailInput {
    userId: string;
    verifyToken: string;
}

export interface ResetPasswordInput {
    userId: string;
    resetToken: string;
    password: string;
    confirmPassword: string;
}

export interface UpdatePasswordInput {
    oldPassword: string;
    newPassword: string;
    confirmPassword: string;
}

export interface AuthToken {
    accessToken: string;
    refreshToken: string;
}

export interface PasswordValidator {
    password: string;
}

export interface UsernameValidator {
    username: string;
}

export interface generateToken {
    userId: string;
    type: string;
}

export interface verificationDetails {
    type: string;
    phone_number?: number;
    email?: string;
}
