// Import required modules and utilities
const express = require("express");
const bcrypt = require("bcryptjs");
const User = require("../models/User");
const { generateAccessToken, generateRefreshToken } = require("../utils/jwt");
const generateUsername = require("../utils/userNameGenerator");
const fetchAvatar = require("../utils/avtarGenerator");

const router = express.Router();
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');

dotenv.config();

/**
 * Route: POST /signup
 * Purpose: Register a new user
 */
router.post("/signup", async (req, res) => {
  const { firstName, lastName, email, phone, password, gender, terms } = req.body;

  try {
    // Normalize email to lowercase
    const normalizedEmail = email.toLowerCase();

    // Step 1: Validate input fields
    if (!firstName) return res.status(400).json({ message: "First Name is required." });
    if (!lastName) return res.status(400).json({ message: "Last Name is required." });
    if (!normalizedEmail) return res.status(400).json({ message: "Email is required." });
    if (!phone) return res.status(400).json({ message: "Phone number is required." });
    if (!password) return res.status(400).json({ message: "Password is required." });
    if (!["Male", "Female"].includes(gender)) return res.status(400).json({ message: "Invalid gender." });
    if (!terms) return res.status(400).json({ message: "Terms must be accepted." });

    // Step 2: Check for existing user by normalized email
    const existingUser = await User.findOne({ email: normalizedEmail });
    if (existingUser) return res.status(400).json({ message: "Email is already registered." });

    // Step 3: Generate a unique username and avatar
    const username = await generateUsername(normalizedEmail);
    const avatar = await fetchAvatar(gender);

    // Step 4: Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Step 5: Create a new user instance
    const newUser = new User({
      firstName,
      lastName,
      email: normalizedEmail, // Store the email in lowercase
      phone,
      password: hashedPassword,
      gender,
      terms,
      username,
      avatar,
      userRole: "user", // Default role for new users
    });

    // Step 6: Save the user to the database
    await newUser.save();

    // Step 7: Respond with a success message
    res.status(201).json({ message: "User successfully created. You can now log in." });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

/**
 * Route: POST /login
 * Purpose: Authenticate a user and generate tokens
 */
router.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    // Normalize email to lowercase
    const normalizedEmail = email.toLowerCase();

    // Step 1: Validate input fields
    if (!normalizedEmail) return res.status(400).json({ message: "Email is required." });
    if (!password) return res.status(400).json({ message: "Password is required." });

    // Step 2: Check for the user in the database using the normalized email
    const user = await User.findOne({ email: normalizedEmail });
    if (!user) return res.status(400).json({ message: "Invalid credentials." });

    // Step 3: Compare the provided password with the stored hashed password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: "Invalid credentials." });

    // Step 4: Generate JWT tokens
    const accessToken = generateAccessToken({ userId: user._id, role: user.userRole });

    // Step 5: Respond with user details and tokens
    res.status(200).json({
      message: "Login successful.",
      accessToken,
      data: {
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        username: user.username,
        avatar: user.avatar,
        phone: user.phone,
        userRole: user.userRole,
      },
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Export the router to use in other parts of the application
module.exports = router;
