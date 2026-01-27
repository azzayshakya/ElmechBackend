// models/Company.js
import mongoose from "mongoose";
import { COMPANY_TYPES } from "./constants.js";

const companySchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
      minlength: 2,
      maxlength: 200,
      index: true
    },

    typeOfCompany: {
      type: String,
      enum: COMPANY_TYPES,
      required: true
    },

    // Basic optional info useful for CRM
    website: { type: String, maxlength: 200 },
    industry: { type: String, maxlength: 100 },
    size: { type: String, maxlength: 50 }, // e.g. "1-10", "11-50", "50-200"
    address: {
      street: { type: String, maxlength: 200 },
      city: { type: String, maxlength: 100 },
      state: { type: String, maxlength: 100 },
      country: { type: String, maxlength: 100 },
      pincode: { type: String, maxlength: 20 }
    },

    createdBy: {
      // who created the company (platform admin or employee)
      type: mongoose.Schema.Types.ObjectId,
      ref: "Employee",
      required: false
    },

    isActive: { type: Boolean, default: true },

    meta: {
      registrationNumber: { type: String, maxlength: 100 },
      notes: { type: String, maxlength: 1000 }
    }
  },
  { timestamps: true }
);

companySchema.index({ name: 1, "address.city": 1 });

export default mongoose.model("Company", companySchema);
