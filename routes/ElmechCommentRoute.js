// routes/commentRoutes.js
const express = require('express');
const router = express.Router();
const addComment = require('../models/ElmechComment');
const dotenv = require('dotenv');

dotenv.config();
// @route   POST api/comments
// @desc    Submit a comment
// @access  Public
router.post('/', async (req, res, next) => {
  try {
    const { firstName, lastName, phone, email, profession, gender, comment } = req.body;

    // Create new comment record
    const newComment = new addComment({
      firstName,
      lastName,
      phone,
      email,
      profession,
      gender,
      comment,
    });

    await newComment.save();
    res.status(201).json({ success: true, message: 'Comment added successfully' });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
