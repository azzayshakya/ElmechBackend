import { z } from "zod";

const objectId = z.string().regex(/^[0-9a-fA-F]{24}$/);
const mobile91 = z.string().regex(/^\+91\d{10}$/);

export const registerSchema = z.object({
  empId: z.string().max(256).optional(),

  gender: z.enum(["male", "female", "other"]).optional(),

  working_status: z.enum([
    "active",
    "on_leave",
    "resigned",
    "terminated"
  ]).optional(),

  userRole: z.enum([
    "admin",
    "ceo",
    "cfo",
    "cto",
    "project_manager",
    "hr_manager",
    "engineer",
    "accountant",
    "employee"
  ]).optional(),

  department: z.enum([
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
  ]).optional(),

  designation: z.enum([
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
  ]).optional(),

  service_type: z.enum([
    "civil_construction",
    "interior_design",
    "electrical_work",
    "plumbing",
    "hvac",
    "fire_safety",
    "landscaping",
    "renovation",
    "consultancy"
  ]).optional(),

  work_location: z.string().max(256).optional(),

  firstName: z.string().min(1).max(256),
  lastName: z.string().min(1).max(256),

  fatherFirstName: z.string().max(256).optional(),
  fatherlastName: z.string().max(256).optional(),

  email: z.string().email().max(256),
  companyEmail: z.string().email().max(256).optional(),

  mobile: mobile91.optional(),
  emergencyContact: mobile91.optional(),

  emergencyContactFName: z.string().max(256),
  emergencyContactLName: z.string().max(256),

  aadharNumber: z
    .string()
    .regex(/^\d{4}-\d{4}-\d{4}$/)
    .optional(),

  joiningDate: z.coerce.date().optional(),
  lastWorkingDate: z.coerce.date().optional(),

  tempAddress: z.string().max(500).optional(),
  permanentAdress: z.string().max(500).optional(),

  bankName: z.string().max(256).optional(),
  ifscCode: z.string().regex(/^[A-Z]{4}0[A-Z0-9]{6}$/).optional(),

  salary: z.number().min(0).max(10000000).optional(),

  accountNumber: z.string().max(18).optional(),

  password: z.string().min(8) // maps to hash + salt generation
});


export const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1)
});
