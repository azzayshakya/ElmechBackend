import { User } from "../models/User.model.js";
import { generateSalt, hashPassword, verifyPassword } from "../utils/password.js";
import { signToken } from "../utils/jwt.js";

export const registerUser = async (data) => {
  const existingUser = await User.findOne({ email: data.email });
  if (existingUser) throw new Error("User already exists");

  const salt = generateSalt();
  const hash = hashPassword(data.password, salt);

  const user = await User.create({
    ...data,
    salt,
    hash
  });

  return user;
};

export const loginUser = async (email, password) => {
  const user = await User.findOne({ email });
  if (!user) throw new Error("Invalid credentials");

  const isValid = verifyPassword(password, user.hash, user.salt);
  if (!isValid) throw new Error("Invalid credentials");

  const token = signToken({
    userId: user._id,
    role: user.userRole
  });

  return { user, token };
};
