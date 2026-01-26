import mongoose from "mongoose";

const commentSchema = new mongoose.Schema(
  {
    commentUuid: {
      type: mongoose.Schema.Types.ObjectId,
      default: () => new mongoose.Types.ObjectId(),
      index: true // UUID lookup, not unique
    },

    fName: {
      type: String,
      maxlength: 256,
      required: true,
      trim: true
    },

    lName: {
      type: String,
      maxlength: 256,
      required: true,
      trim: true
    },

    email: {
      type: String,
      maxlength: 256,
      required: true,
      lowercase: true,
      trim: true,
      match: [/^\S+@\S+\.\S+$/, "Invalid email"]
    },

    mobile: {
      type: String,
      maxlength: 13,
      required: true,
      match: [/^\+91[6-9]\d{9}$/, "Invalid Indian mobile number"]
    },

    comment: {
      type: String,
      maxlength: 800,
      required: true,
      trim: true
    },
    project_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Project",
      index: true
    },
    star: { type: Boolean, default: false },
    created_by: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User"
    },

    created_at: {
      type: Date,
      default: () => new Date().setHours(0, 0, 0, 0),
      immutable: true
    }
  },
  { timestamps: false }
);

/* useful indexes */
commentSchema.index({ project_id: 1, created_at: -1 });

const Comment = mongoose.model("Comment", commentSchema);
export default Comment;
