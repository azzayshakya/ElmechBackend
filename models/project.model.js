// models/Project.js
import mongoose from "mongoose";
import { PROJECT_STATUSES } from "./constants.js";

const allocationSubSchema = new mongoose.Schema(
  {
    employee: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Employee",
      required: true
    },
    roleInProject: { type: String, maxlength: 100 },
    allocationPercent: {
      type: Number,
      min: 0,
      max: 100,
      required: true
    },
    assignedAt: { type: Date, default: Date.now }
  },
  { _id: false }
);

const projectSchema = new mongoose.Schema(
  {
    // This schema represents both proposals and active projects (same entity)
    title: {
      type: String,
      required: true,
      trim: true,
      minlength: 3,
      maxlength: 200,
      index: true
    },

    description: {
      type: String,
      required: true,
      maxlength: 5000
    },

    clientCompany: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Company",
      required: true,
      index: true
    },

    vendorCompany: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Company",
      required: function () {
        // vendor can be assigned later; allow null at proposal creation
        return false;
      },
      default: null,
      index: true
    },

    // Keep allocations and assigned employees as subdocs
    assignedEmployees: {
      type: [allocationSubSchema],
      default: []
    },

    status: {
      type: String,
      enum: PROJECT_STATUSES,
      default: "proposed_by_client",
      required: true,
      index: true
    },

    // Proposal fields (also useful during project lifecycle)
    estimatedBudget: { type: Number, min: 0 },
    estimatedDuration: { type: String, maxlength: 100 }, // e.g. "3 months"
    attachments: [{ type: String, maxlength: 1000 }], // urls or storage keys

    // Dates for lifecycle
    proposedAt: { type: Date, default: Date.now },
    startedAt: { type: Date },
    completedAt: { type: Date },

    // small audit fields
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "Employee" },
    vendorAcceptedAt: { type: Date },

    internalNotes: { type: String, maxlength: 2000 }
  },
  { timestamps: true }
);

// Useful indexes
projectSchema.index({ clientCompany: 1, vendorCompany: 1 });
projectSchema.index({ status: 1, proposedAt: -1 });

export default mongoose.model("Project", projectSchema);

// If you want an explicit "ProjectProposal" model (same schema), you can register it too:
export const ProjectProposal = mongoose.model("ProjectProposal", projectSchema);
