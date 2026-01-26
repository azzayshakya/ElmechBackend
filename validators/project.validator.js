import { z } from "zod";

export const PROJECT_ADMIN_ROLES = [
  "admin",
  "ceo",
  "cfo",
  "cto",
  "project_manager"
];


export const createProjectSchema = z.object({
    projectName: z.string().min(1).max(256),
    clientName: z.string().min(1).max(256),
    clientMobile: z.string().regex(/^\+91[6-9]\d{9}$/).optional(),
    services: z.array(z.enum([
        "civil_construction",
        "interior_design",
        "electrical_work",
        "plumbing",
        "hvac",
        "fire_safety",
        "landscaping",
        "renovation",
        "consultancy"
    ])).optional(),
    projectAddress: z.string().max(500).optional(),
    description: z.string().min(1).max(800),
    budget: z.number().min(0).max(100000000),
    startDate: z.coerce.date(),
    endDate: z.coerce.date().optional(),
    lead: z.array(
        z.object({
            user_id: z.string().refine(id => mongoose.Types.ObjectId.isValid(id))
        })
    ).optional(),
    coLead: z.array(
        z.object({
            user_id: z.string().refine(id => mongoose.Types.ObjectId.isValid(id))
        })
    ).optional()
});


export const updateProjectSchema = createProjectSchema.partial();


export const listProjectSchema = z.object({
    page: z.coerce.number().int().positive().default(1),
    limit: z.coerce.number().int().positive().max(100).default(10),
    status: z.enum([
        "planned",
        "ongoing",
        "on_hold",
        "completed",
        "cancelled"
    ]).optional(),
    department: z.enum([
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
    name: z.string().optional(),
    order: z.enum(["asc", "desc"]).default("desc")
});