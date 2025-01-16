// Import the 'jsonwebtoken' module for handling JWT (JSON Web Tokens)
const jwt = require("jsonwebtoken");
const dotenv = require('dotenv');

dotenv.config();
/**
 * Function: generateAccessToken
 * Purpose: Generate a short-lived access token for user authentication.
 * 
 * Steps:
 *  1. Accept a payload (e.g., user details or claims) as an argument.
 *  2. Use the `sign` method from the `jsonwebtoken` library to create the token.
 *  3. Set the token expiration to 15 minutes (`expiresIn: "15m"`).
 *  4. Sign the token using the secret key stored in `ACCESS_TOKEN_SECRET` environment variable.
 * 
 * @param {Object} payload - Data to include in the JWT payload (e.g., user ID, role).
 * @returns {string} - A signed JWT access token.
 */
const generateAccessToken = (payload) => {
  return jwt.sign(
    payload, // The data to encode in the JWT
    process.env.ACCESS_TOKEN_SECRET, // Secret key for signing the token
    { expiresIn:process.env.ACCESS_TOKEN_EXPIRY || '1d' } // Token expiration time
  );
};

/**
 * Function: generateRefreshToken
 * Purpose: Generate a long-lived refresh token for obtaining new access tokens.
 * 
 * Steps:
 *  1. Accept a user ID as an argument to uniquely identify the user.
 *  2. Use the `sign` method from the `jsonwebtoken` library to create the token.
 *  3. Set the token expiration to 7 days (`expiresIn: "7d"`).
 *  4. Sign the token using the secret key stored in `REFRESH_TOKEN_SECRET` environment variable.
 * 
 * @param {string} userId - The unique identifier of the user.
 * @returns {string} - A signed JWT refresh token.
 */
const generateRefreshToken = (userId) => {
  // console.log("generateRefreshToken is called for the ", userId )
  return jwt.sign(
    { userId }, // The data to encode in the JWT (user ID in this case)
    process.env.REFRESH_TOKEN_SECRET, // Secret key for signing the token
    { expiresIn: process.env.REFRESH_TOKEN_EXPIRY || '7d' } // Token expiration time
  );
  
};

// Export the functions for use in other parts of the application
module.exports = {
  generateAccessToken, // Function to generate access tokens
  generateRefreshToken, // Function to generate refresh tokens
};
