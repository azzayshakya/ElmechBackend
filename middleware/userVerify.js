const jwt = require('jsonwebtoken');
const User = require('../models/User');

/**
 * Middleware to protect routes by validating the user's JWT and checking their role.
 *
 * @param {Object} req - The HTTP request object.
 * @param {Object} res - The HTTP response object.
 * @param {Function} next - Callback to pass control to the next middleware.
 * @param {Array} allowedRoles - Array of roles that are allowed to access the route.
 * 
 * @throws {Error} Returns 401 or 404 HTTP status with a descriptive error message if:
 *  1. Token is not provided.
 *  2. Token is invalid or expired.
 *  3. User associated with the token is not found.
 *  4. User's role does not match the allowed roles.
 */
const protect = (allowedRoles = []) => async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Authorization token required' });
  }

  try {
    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

    // Find the user in the database using the userId from the token
    const user = await User.findById(decoded.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not foun' });
    }

    // Attach the user object to the request for downstream use
    req.user = user;

    // Check if the user's role is in the allowedRoles array
    if (allowedRoles.length && !allowedRoles.includes(user.userRole)) {


      return res.status(403).json({ message: 'Access forbidden: Insufficient privileges' });
    }

    // Pass control to the next middleware or route handler
    next();
  } catch (error) {
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
};

module.exports = protect;

