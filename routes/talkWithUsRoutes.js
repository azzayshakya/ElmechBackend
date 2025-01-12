// routes/talkWithUsRoutes.js
const express = require('express');
const router = express.Router();
const TalkWithUs = require('../models/TalkWithUs');

// @route   POST api/talk-with-us
// @desc    Submit a "Get in Touch" form
// @access  Publicrouter.post('/', async (req, res, next) => {
  router.post('/', async (req, res, next) => {
    try {
      const { name, email, mobile, location, message } = req.body;
  
      // Create new "Get in Touch" record
      const newMessage = new TalkWithUs({
        name,
        email,
        mobile,
        location,
        message,
      });
  
      await newMessage.save();
      res.status(201).json({ success: true, message: 'Message sent successfully' });
    } catch (err) {
      next(err);
    }
  });
  
  module.exports = router;