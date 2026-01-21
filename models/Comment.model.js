import mongoose from "mongoose";

const commentSchema = new mongoose.Schema({

  commentUuid: {
    type: mongoose.Schema.Types.ObjectId,
    default: () => new mongoose.Types.ObjectId(),
    unique: true
  },
  fName: {
    type: String,
    maxlength: 256,
    required: true
  },
  lName: {
    type: String,
    maxlength: 256,
    required: true
  },
  email: {
    type: String,
    maxlength: 256,
    required: true,
    lowercase: true
  },
  mobile: {
    type: String,//+91 format
    maxlength: 13,
    required: true
  },
  comment: {
    type: String,
    maxlength: 800,
    required: true
  },
  project_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Project"
  },
  created_by: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User"
  },
  created_at: {
    type: Date,
    default: () => new Date().setHours(0, 0, 0, 0)
  }
});

const Comment = mongoose.model("Comment", commentSchema);

export default Comment;