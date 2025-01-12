// Import required modules and utilities
const express = require("express"); // Express framework for creating routes
const bcrypt = require("bcryptjs"); // Library for hashing passwords
const User = require("../models/User"); // User model to interact with the database
const { generateAccessToken, generateRefreshToken } = require("../utils/jwt"); // Functions to generate JWT tokens
const generateUsername = require("../utils/userNameGenerator"); // Utility to generate unique usernames
const fetchAvatar = require("../utils/avtarGenerator"); // Utility to fetch user avatars

const router = express.Router(); // Create an instance of the Express router
const dotenv = require('dotenv');

dotenv.config();
/**
 * Route: POST /signup
 * Purpose: Register a new user
 * 
 * Steps:
 *  1. Extract user details from the request body.
 *  2. Validate required fields.
 *  3. Check if the email is already registered.
 *  4. Generate a unique username and avatar.
 *  5. Hash the user's password.
 *  6. Save the new user in the database.
 *  7. Send a success response or handle errors.
 */
router.post("/signup", async (req, res) => {
  console.log("creating the account")
  const { firstName, lastName, email, phone, password, gender, terms } = req.body;

  try {
    // Step 1: Validate input fields
    if (!firstName) return res.status(400).json({ message: "First Name is required." });
    if (!lastName) return res.status(400).json({ message: "Last Name is required." });
    if (!email) return res.status(400).json({ message: "Email is required." });
    if (!phone) return res.status(400).json({ message: "Phone number is required." });
    if (!password) return res.status(400).json({ message: "Password is required." });
    if (!["Male", "Female"].includes(gender)) return res.status(400).json({ message: "Invalid gender." });
    if (!terms) return res.status(400).json({ message: "Terms must be accepted." });

    // Step 2: Check for existing user by email
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: "Email is already registered." });

    // Step 3: Generate a unique username and avatar
    const username = await generateUsername(email);
    const avatar = await fetchAvatar(gender);

    // Step 4: Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Step 5: Create a new user instance
    const newUser = new User({
      firstName,
      lastName,
      email,
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
    // Handle errors and respond with an appropriate message
    res.status(500).json({ message: error.message });
  }
});

/**
 * Route: POST /login
 * Purpose: Authenticate a user and generate tokens
 * 
 * Steps:
 *  1. Extract email and password from the request body.
 *  2. Validate input fields.
 *  3. Check if the user exists in the database.
 *  4. Compare the provided password with the stored hashed password.
 *  5. Generate access and refresh tokens upon successful authentication.
 *  6. Send user details and tokens in the response.
 */
router.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    // Step 1: Validate input fields
    if (!email) return res.status(400).json({ message: "Email is required." });
    if (!password) return res.status(400).json({ message: "Password is required." });

    // Step 2: Check for the user in the database
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "Invalid credentials." });

    // Step 3: Compare the provided password with the stored hashed password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: "Invalid credentials." });

    // Step 4: Generate JWT tokens
    const accessToken = generateAccessToken({ userId: user._id, role: user.userRole });
    const refreshToken = generateRefreshToken(user._id);



    
       // Set refresh token in HTTP-only cookie
      //  res.cookie('refreshToken', refreshToken, {
      //   httpOnly: true,
      //   secure: process.env.NODE_ENV === 'production', // Use HTTPS in production
      //   sameSite: 'strict', // Cross-site request protection
      //   maxAge: parseInt(process.env.COOKIE_MAX_AGE, 10),
      // });

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
    // Handle errors and respond with an appropriate message
    res.status(500).json({ message: error.message });
  }
});

// Export the router to use in other parts of the application
module.exports = router;
