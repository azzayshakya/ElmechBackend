// Import the User model for database operations
const User = require("../models/User");
const dotenv = require('dotenv');

dotenv.config();
/**
 * Function: generateUsername
 * Purpose: Generate a unique username based on the user's email address.
 * 
 * Steps:
 *  1. Extract the portion of the email before the "@" symbol as the base username.
 *  2. Check if the username already exists in the database.
 *  3. If the username exists, append a numeric counter to the base username and increment the counter until a unique username is found.
 *  4. Return the unique username.
 * 
 * @param {string} email - The email address of the user.
 * @returns {Promise<string>} - A unique username.
 */
const generateUsername = async (email) => {
  // Extract the portion of the email before the '@' symbol as the base username
  const baseUsername = email.split("@")[0];
  let username = baseUsername; // Initial username to check for uniqueness
  let counter = 1; // Counter to append for generating unique usernames

  // Check for existing usernames in the database and modify the username if needed
  while (await User.findOne({ username })) {
    /**
     * If the username already exists:
     *  - Append the counter to the base username.
     *  - Increment the counter for the next iteration.
     */
    username = `${baseUsername}${counter}`;
    counter++;
  }

  // Return the unique username
  return username;
};

// Export the function for use in other parts of the application
module.exports = generateUsername;
