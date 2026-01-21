import mongoose from "mongoose";

import { updateHistorySchema } from "./user"

const querySchema = new mongoose.Schema({
  queryUuid: {
    type: mongoose.Schema.Types.ObjectId,
    default: () => new mongoose.Types.ObjectId(),
    unique: true
  },
  fName: {
    type: String,
    maxlength: 256,
    required: true
  },
  l_name: {
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
  subject: {
    type: String,
    enum: [
      'general_inquiry',
      'service_request',
      'quotation',
      'complaint',
      'feedback',
      'project_update',
      'technical_support',
      'billing',
      'partnership'
    ]
  },
  description: {
    type: String,
    maxlength: 800,
    required: true
  },
  status: {
    type: String,
    enum: [
      'pending',
      'in_progress',
      'resolved',
      'closed'
    ]
  },
  created_at: {
    type: Date,
    default: () => new Date().setHours(0, 0, 0, 0)
  },
  created_by: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User"
  },
  update_history: [updateHistorySchema]
});


const Query =
  mongoose.models.Query || mongoose.model("Query", querySchema);

export default Query;