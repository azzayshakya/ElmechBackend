import mongoose from "mongoose";

import { updateHistorySchema } from "./user"

const projectSchema = new mongoose.Schema({
  projectId: {
    type: mongoose.Schema.Types.ObjectId,
    default: () => new mongoose.Types.ObjectId(),
    index: true
  }
  ,
  projectName: {
    type: String,
    maxlength: 256,
    required: true
  },
  clientName: {
    type: String,
    maxlength: 256,
    required: true
  },
  clientMobile: {
    type: String,//+91 format
    maxlength: 13
  },
  services: [{
    type: String,
    enum: [
      'civil_construction',
      'interior_design',
      'electrical_work',
      'plumbing',
      'hvac',
      'fire_safety',
      'landscaping',
      'renovation',
      'consultancy'
    ]
  }],
  projectAddress: {
    type: String,
    maxlength: 500
  },
  description: {
    type: String,
    maxlength: 800,
    required: true
  },
  budget: {
    type: Number,
    min: 0,
    max: 100000000,
    required: true
  },
  startDate: {
    type: Date,
    required: true
  },
  endDate: {
    type: Date
  },

  created_at: {
    type: Date,
    default: () => new Date().setHours(0, 0, 0, 0),
    immutable: true
  },

  projectStatus: {
    type: String,
    enum: ["planned", "ongoing", "on_hold", "completed", "cancelled"],
    default: "planned"
  },

  lead: [
    {
      user_id: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: true
      }
    }
  ],
  coLead: [
    {
      user_id: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: true
      }
    }
  ],
  created_by: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true
  },
  created_at: {
    type: Date,
    default: () => new Date().setHours(0, 0, 0, 0)
  },
  update_history: [updateHistorySchema]
});

const Project =
  mongoose.models.Project || mongoose.model("Project", projectSchema);

export default Project;