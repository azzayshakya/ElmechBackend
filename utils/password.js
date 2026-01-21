import crypto from "crypto";

export const generateSalt = () =>
  crypto.randomBytes(16).toString("hex");

export const hashPassword = (password, salt) =>
  crypto
    .pbkdf2Sync(password, salt, 10000, 64, "sha512")
    .toString("hex");

export const verifyPassword = (password, hash, salt) =>
  hash === hashPassword(password, salt);
