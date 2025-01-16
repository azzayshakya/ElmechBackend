const express = require('express');
const router = express.Router();
const ElmechComment = require('../models/ElmechComment');
const protect = require('../middleware/userVerify');
// @route   GET api/comments
// @desc    Get all comments submitted by users
// @access  Public
router.get('/', protect(['admin']), async (req, res, next) => {
  try {
    const comments = await ElmechComment.find(); // Retrieve all comments from the "ElmechComment" collection
    if (!comments || comments.length === 0) {
      return res.status(404).json({ message: 'No comments found' });
    }

    res.status(200).json(comments); // Send all the comments in the response
  } catch (err) {
    next(err); // Pass any errors to the global error handler
  }
});

module.exports = router;
