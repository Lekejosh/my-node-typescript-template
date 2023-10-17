interface RegisterInput {
    name: string;
    email: string;
    password: string;
    dateOfBirth: Date;
    gender: string;
    termsOfService: boolean;
}

interface LoginInput {
    email: string;
    password: string;
}

interface GenerateTokenInput {
    userId: string;
    role: string;
}

interface RefreshTokenInput {
    refreshToken: string;
}

interface LogoutInput {
    refreshToken: string;
}

interface VerifyEmailInput {
    userId: string;
    verifyToken: string;
}

interface ResetPasswordInput {
    userId: string;
    resetToken: string;
    password: string;
    confirmPassword: string;
}

interface UpdatePasswordInput {
    oldPassword: string;
    newPassword: string;
    confirmPassword: string;
}

interface AuthToken {
    accessToken: string;
    refreshToken: string;
}

interface PasswordValidator {
    password: string;
}

interface generateToken {
    userId: string;
    type: string;
}
