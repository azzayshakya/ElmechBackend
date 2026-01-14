import mongoose from "mongoose";

const updateHistorySchema = new mongoose.Schema(
  {
    field: { type: String, required: true },
    old_value: { type: mongoose.Schema.Types.Mixed },
    new_value: { type: mongoose.Schema.Types.Mixed },
    updated_at: { type: Date, default: Date.now },
    updated_by: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User"
    }
  },
  { _id: false }
);

const userSchema = new mongoose.Schema({
  user_id: {
    type: mongoose.Schema.Types.ObjectId,
    default: () => new mongoose.Types.ObjectId(),
    unique: true
  },
  empId: {
    type: String,
    maxlength: 256,
    unique: true
  },
  gender: {
    type: String,
    enum: [
      "male",
      "female",
      "other"
    ]
  },
  working_status: {
    type: String,
    enum: [
      "active",
      "on_leave",
      "resigned",
      "terminated"
    ]
  },
  userRole: {
    type: String,
    enum: [
      "admin",//Admin Dashboard Access
      "ceo",//Admin Dashboard Access
      "cfo",//Admin Dashboard Access
      "cto",
      "project_manager",
      "hr_manager",
      "engineer",
      "accountant",
      "employee"//Admin Dashboard Access
    ],
    default: "default_user"
  },
  department: {
    type: String,
    enum: [
      'engineering',
      'construction',
      'design',
      'project_management',
      'quality_control',
      'safety',
      'procurement',
      'finance',
      'hr',
      'admin',
      'marketing',
      'sales'
    ]
  },
  designation: {
    type: String,
    enum: [
      'project_manager',
      'site_engineer',
      'civil_engineer',
      'mechanical_engineer',
      'electrical_engineer',
      'architect',
      'designer',
      'supervisor',
      'foreman',
      'technician',
      'accountant',
      'hr_manager',
      'admin_staff'
    ]
  },
  service_type: {
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
  },
  work_location: {
    type: String,
    maxlength: 256
  },
  firstName: {
    type: String,
    maxlength: 256,
    required: true
  },
  lastName: {
    type: String,
    maxlength: 256,
    required: true
  },
  fatherFirstName: {
    type: String,
    maxlength: 256
  },
  fatherlastName: {
    type: String,
    maxlength: 256
  },
  email: {
    type: String,
    maxlength: 256,
    unique: true,
    required: true,
    lowercase: true
  },
  companyEmail: {
    type: String,
    maxlength: 256,
    unique: true,
    lowercase: true
  },
  mobile: {
    type: String,//+91 format
    maxlength: 13
  },
  emergencyContact: {
    type: String,//+91 format
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
    type: String,//1234-5678-9012
    maxlength: 14
  },
  joiningDate: {
    type: Date,
    default: () => new Date().setHours(0, 0, 0, 0)
  },
  lastWorkingDate: {
    type: Date,
    default: () => new Date().setHours(0, 0, 0, 0)
  },
  tempAddress: {
    type: String,
    maxlength: 500
  },
  permanentAdress: {
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
    range: [0, 10000000]
  },
  accountNumber: {
    type: String,
    maxlength: 18,
    uppercase: true
  },
  hash: { type: String, required: true },
  salt: { type: String, required: true },

  created_at: {
    type: Date,
    default: () => new Date().setHours(0, 0, 0, 0)
  },

  update_history: [updateHistorySchema]
});

import mongoose from "mongoose";

const User = mongoose.model("User", userSchema);

export { User, updateHistorySchema };
