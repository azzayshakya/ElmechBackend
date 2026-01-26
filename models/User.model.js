import mongoose from "mongoose";

/* ===========================
   Update History Sub-Schema
=========================== */
const updateHistorySchema = new mongoose.Schema(
  {
    field: { type: String, required: true },
    old_value: mongoose.Schema.Types.Mixed,
    new_value: mongoose.Schema.Types.Mixed,
    updated_at: { type: Date, default: Date.now },
    updated_by: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User"
    }
  },
  { _id: false }
);

/* ===========================
   User Schema
=========================== */
const userSchema = new mongoose.Schema(
  {
    /* MongoDB already provides _id → NO need for user_id */
    empId: {
      type: String,
      maxlength: 256,
      default: null
    },

    gender: {
      type: String,
      enum: ["male", "female", "other"]
    },

    working_status: {
      type: String,
      enum: ["active", "on_leave", "resigned", "terminated"],
      default: "active"
    },

    userRole: {
      type: String,
      enum: [
        "admin",
        "ceo",
        "cfo",
        "cto",
        "project_manager",
        "hr_manager",
        "engineer",
        "accountant",
        "employee",
        "default_user"
      ],
      default: "default_user"
    },

    department: {
      type: String,
      enum: [
        "engineering",
        "construction",
        "design",
        "project_management",
        "quality_control",
        "safety",
        "procurement",
        "finance",
        "hr",
        "admin",
        "marketing",
        "sales"
      ]
    },

    designation: {
      type: String,
      enum: [
        "project_manager",
        "site_engineer",
        "civil_engineer",
        "mechanical_engineer",
        "electrical_engineer",
        "architect",
        "designer",
        "supervisor",
        "foreman",
        "technician",
        "accountant",
        "hr_manager",
        "admin_staff"
      ]
    },

    service_type: {
      type: String,
      enum: [
        "civil_construction",
        "interior_design",
        "electrical_work",
        "plumbing",
        "hvac",
        "fire_safety",
        "landscaping",
        "renovation",
        "consultancy"
      ]
    },

    work_location: {
      type: String,
      maxlength: 256
    },

    firstName: {
      type: String,
      maxlength: 256,
      required: true,
      trim: true
    },

    lastName: {
      type: String,
      maxlength: 256,
      required: true,
      trim: true
    },

    fatherFirstName: {
      type: String,
      maxlength: 256
    },

    fatherLastName: {
      type: String,
      maxlength: 256
    },

    email: {
      type: String,
      maxlength: 256,
      required: true,
      lowercase: true,
      trim: true
    },

    companyEmail: {
      type: String,
      maxlength: 256,
      lowercase: true,
      trim: true,
      default: null
    },

    mobile: {
      type: String,
      maxlength: 13
    },

    emergencyContact: {
      type: String,
      maxlength: 13
    },

    emergencyContactFName: {
      type: String,
      maxlength: 256,
      required: true
    },

    emergencyContactLName: {
      type: String,
      maxlength: 256,
      required: true
    },

    aadharNumber: {
      type: String,
      maxlength: 14,
      default: null
    },

    joiningDate: {
      type: Date,
      default: () => new Date().setHours(0, 0, 0, 0)
    },

    lastWorkingDate: {
      type: Date
    },

    tempAddress: {
      type: String,
      maxlength: 500
    },

    permanentAddress: {
      type: String,
      maxlength: 500
    },

    bankName: {
      type: String,
      maxlength: 256
    },

    ifscCode: {
      type: String,
      uppercase: true,
      maxlength: 11
    },

    salary: {
      type: Number,
      min: 0,
      max: 10000000
    },

    accountNumber: {
      type: String,
      maxlength: 18
    },

    hash: { type: String, required: true },
    salt: { type: String, required: true },

    update_history: [updateHistorySchema]
  },
  {
    timestamps: {
      createdAt: "created_at",
      updatedAt: "updated_at"
    }
  }
);


userSchema.index(
  { empId: 1 },
  {
    unique: true,
    partialFilterExpression: {
      empId: { $exists: true, $ne: null }
    }
  }
);

// email → always unique
userSchema.index(
  { email: 1 },
  { unique: true }
);

// companyEmail → unique only if present
userSchema.index(
  { companyEmail: 1 },
  {
    unique: true,
    partialFilterExpression: {
      companyEmail: { $exists: true, $ne: null }
    }
  }
);

// aadhar → unique only if present
userSchema.index(
  { aadharNumber: 1 },
  {
    unique: true,
    partialFilterExpression: {
      aadharNumber: { $exists: true, $ne: null }
    }
  }
);

const User = mongoose.model("User", userSchema);

export { User, updateHistorySchema };
