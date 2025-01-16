const mongoose = require('mongoose');
const dotenv = require('dotenv');

// Load environment variables from .env file
dotenv.config();

/**
 * Establishes a connection to the MongoDB database.
 * Reads the connection URI from the environment variable `MONGODB_URI`.
 */
const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,    // Use the new URL parser to avoid deprecation warnings
      useUnifiedTopology: true // Use the new server discovery and monitoring engine
    });
    console.log('MongoDB connected successfully');
  } catch (error) {
    console.error(`MongoDB connection failed: ${error.message}`); // Log error message
    process.exit(1); // Exit process with failure code
  }
};

module.exports = connectDB;
