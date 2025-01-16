const express = require('express');
const router = express.Router();
const TalkWithUs = require('../models/TalkWithUs');
const protect = require('../middleware/userVerify');


router.get('/',protect(['admin']), async (req, res, next) => {
  try {
    const queries = await TalkWithUs.find(); // Retrieve all user queries

    if (!queries) {
      return res.status(404).json({ message: 'No queries found' });
    }

    res.status(200).json(queries);
  } catch (err) {
    next(err); // Pass errors to the error handler middleware
  }
});

module.exports = router;
