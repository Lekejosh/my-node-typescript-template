interface UserDataInput {
  name?: string;
  email?: string;
  image: {
    url: string;
    public_id: string;
  };
  password?: string;
  role?: "user" | "admin";
  gender?: string;
  dateOfBirth?: Date;
  termsOfServices?: boolean;
}

interface UserCreateInput {
  name?: string;
  email?: string;
  password?: string;
  role?: "user" | "admin";
  gender?: string;
  dateOfBirth?: Date;
  termsOfServices?: boolean;
}

interface UserUpdateInput {
  name?: string;
  image?: string;
}
