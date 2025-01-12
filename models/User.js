// src/models/User.js
const mongoose = require("mongoose");

// Define the User schema with necessary fields
const userSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  phone: { type: String, required: true },
  password: { type: String, required: true },
  gender: { type: String, enum: ["Male", "Female"], required: true },
  terms: { type: Boolean, required: true },
  username: { type: String, required: true, unique: true },
  avatar: { type: String },
  userRole: { type: String, default: "user" }, // User role defaults to "user"
});

module.exports = mongoose.model("User", userSchema);
