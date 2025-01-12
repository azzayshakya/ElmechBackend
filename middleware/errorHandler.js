/**
 * Error handling middleware for Express applications.
 * Logs the error and sends a formatted response to the client.
 *
 * @param {Error} err - The error object.
 * @param {Request} req - The incoming request object.
 * @param {Response} res - The outgoing response object.
 * @param {Function} next - The next middleware function.
 */
const errorHandler = (err, req, res, next) => {
  // Log the full error stack to the server console
  console.error('Error Stack:', err.stack);

  // Set the HTTP status code (default to 500 if not specified)
  const statusCode = err.statusCode || 500;

  // Send a JSON response with error details
  res.status(statusCode).json({
    success: false,             // Indicates the failure of the request
    message: err.message || 'Server Error', // Use the error message or a generic fallback
  });
};

module.exports = errorHandler;
// in index.js call it after all the routes