import { z } from "zod";


export const createQuerySchema = z.object({
    fName: z.string().min(1).max(256),
    lName: z.string().min(1).max(256),
    email: z.string().email(),
    mobile: z.string().regex(/^\+91[6-9]\d{9}$/),
    subject: z.enum([
        "general_inquiry",
        "service_request",
        "quotation",
        "complaint",
        "feedback",
        "project_update",
        "technical_support",
        "billing",
        "partnership"
    ]),
    description: z.string().min(1).max(800)
});

export const listQuerySchema = z.object({
    page: z.coerce.number().int().positive().default(1),
    limit: z.coerce.number().int().positive().max(100).default(10),
    search: z.string().optional(),
    star: z.enum(["true", "false"]).optional(),
    status: z.enum([
        "pending",
        "in_progress",
        "resolved",
        "closed"
    ]).optional(),
    sortBy: z.enum([
        "created_at",
        "status",
        "star"
    ]).default("created_at"),
    order: z.enum(["asc", "desc"]).default("desc")
});


export const starQuerySchema = z.object({
    star: z.boolean()
});