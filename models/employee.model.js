// models/Employee.js
import mongoose from "mongoose";
import { EMPLOYEE_ROLES } from "./constants.js";

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const employeeSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
      minlength: 2,
      maxlength: 100
    },

    email: {
      type: String,
      required: true,
      trim: true,
      lowercase: true,
      maxlength: 254,
      match: emailRegex,
      index: { unique: true, sparse: true } // sparse so platform-admins can be null if needed
    },

    // authentication: store hashed password and salt (no plaintext)
    hashedPassword: {
      type: String,
      required: true,
      minlength: 60, // bcrypt hashes ~60 chars; keep flexible
      maxlength: 200
    },
    salt: {
      type: String,
      required: true,
      maxlength: 200
    },

    role: {
      type: String,
      enum: EMPLOYEE_ROLES,
      required: true
    },

    company: {
      // CEO and other company-scoped employees
      type: mongoose.Schema.Types.ObjectId,
      ref: "Company",
      default: null,
      required: function () {
        // platform-level "admin" could be null; enforce company for other roles
        return this.role !== "admin";
      }
    },

    phone: {
      type: String,
      trim: true,
      maxlength: 20
    },

    isActive: { type: Boolean, default: true },

    profile: {
      designation: { type: String, maxlength: 100 },
      joiningDate: { type: Date },
      bio: { type: String, maxlength: 1000 }
    },

    // For audit/history
    lastLoginAt: { type: Date }
  },
  { timestamps: true }
);

// helpful index for company lookups
employeeSchema.index({ company: 1, role: 1 });

export default mongoose.model("Employee", employeeSchema);
