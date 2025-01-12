const express = require("express"); // Express framework for creating routes
const jwt = require("jsonwebtoken"); // Import jsonwebtoken package for JWT functionality
const User = require("../models/User"); // User model to interact with the database
const { generateAccessToken } = require("../utils/jwt"); // Functions to generate JWT tokens

const dotenv = require("dotenv");

dotenv.config();
const router = express.Router();

// Refresh route to get a new access token
router.post("/refresh", async (req, res) => {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken)
    return res.status(401).json({ message: "No refresh token provided" });

  try {
    const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);

    // Check if user exists
    const user = await User.findById(decoded.userId);
    if (!user)
      return res.status(404).json({ message: "User not found for refresh token" });

    // Generate new access token
    const accessToken = generateAccessToken({ userId: user._id, role: user.role });
    console.log("new accesstoken on the refresh token call", accessToken);

    res.status(200).json({
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
    console.log(error);
    res.status(401).json({ message: "Invalid or expired refresh token" });
  }
});

module.exports = router;
