// models/Comment.js
const mongoose = require('mongoose');

const CommentSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  phone: { type: String, required: true },
  email: { type: String, required: true },
  profession: { type: String, required: true },
  gender: { type: String, required: true },
  comment: { type: String, required: true },
},
{ timestamps: true }
);

module.exports = mongoose.model('ElmechComment', CommentSchema);
