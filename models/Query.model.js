import mongoose from "mongoose";
import { updateHistorySchema } from "./user";

const querySchema = new mongoose.Schema(
  {
    queryUuid: {
      type: mongoose.Schema.Types.ObjectId,
      default: () => new mongoose.Types.ObjectId(),
      index: true
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

    subject: {
      type: String,
      enum: [
        "general_inquiry",
        "service_request",
        "quotation",
        "complaint",
        "feedback",
        "project_update",
        "technical_support",
        "billing",
        "partnership"
      ],
      required: true
    },

    description: {
      type: String,
      maxlength: 800,
      required: true,
      trim: true
    },
    star: { type: Boolean, default: false },
    status: {
      type: String,
      enum: ["pending", "in_progress", "resolved", "closed"],
      default: "pending"
    },

    created_at: {
      type: Date,
      default: () => new Date().setHours(0, 0, 0, 0),
      immutable: true
    },

    created_by: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User"
    },

    update_history: [updateHistorySchema]
  },
  { timestamps: false }
);

/* query performance indexes */
querySchema.index({ email: 1 });
querySchema.index({ mobile: 1 });
querySchema.index({ status: 1, created_at: -1 });

const Query =
  mongoose.models.Query || mongoose.model("Query", querySchema);

export default Query;
