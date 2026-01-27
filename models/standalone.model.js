// models/StandaloneUser.js
import mongoose from "mongoose";

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const standaloneUserSchema = new mongoose.Schema(
  {
    name: { type: String, trim: true, maxlength: 100 },
    email: {
      type: String,
      required: true,
      trim: true,
      lowercase: true,
      maxlength: 254,
      match: emailRegex,
      index: { unique: true }
    },
    // optional auth fields for future - keep hashed storage if used
    hashedPassword: { type: String, maxlength: 200 },
    salt: { type: String, maxlength: 200 },
    bio: { type: String, maxlength: 1000 }
  },
  { timestamps: true }
);

export default mongoose.model("StandaloneUser", standaloneUserSchema);
