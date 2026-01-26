import Query from "../models/query.js";
import { createQuerySchema, listQuerySchema, starQuerySchema } from "../validators/query.validator.js";


export const createQuery = async (req, res) => {
    try {
        const data = createQuerySchema.parse(req.body);

        const query = await Query.create({
            ...data
        });

        res.status(201).json({
            success: true,
            message: "Query submitted successfully",
            data: query
        });

    } catch (err) {
        res.status(400).json({
            success: false,
            message: err.errors?.[0]?.message || err.message
        });
    }
};


export const listQueries = async (req, res) => {
    try {
        const params = listQuerySchema.parse(req.query);

        const {
            page,
            limit,
            search,
            star,
            status,
            sortBy,
            order
        } = params;

        const filter = {};

        if (star !== undefined) {
            filter.star = star === "true";
        }

        if (status) {
            filter.status = status;
        }

        if (search) {
            filter.$or = [
                { fName: { $regex: search, $options: "i" } },
                { lName: { $regex: search, $options: "i" } },
                { email: { $regex: search, $options: "i" } },
                { mobile: { $regex: search, $options: "i" } },
                { subject: { $regex: search, $options: "i" } }
            ];
        }

        const skip = (page - 1) * limit;
        const sortOrder = order === "asc" ? 1 : -1;

        const [queries, total] = await Promise.all([
            Query.find(filter)
                .sort({ [sortBy]: sortOrder })
                .skip(skip)
                .limit(limit),
            Query.countDocuments(filter)
        ]);

        res.status(200).json({
            success: true,
            data: queries,
            pagination: {
                total,
                page,
                limit,
                totalPages: Math.ceil(total / limit)
            }
        });

    } catch (err) {
        res.status(400).json({
            success: false,
            message: err.errors?.[0]?.message || err.message
        });
    }
};


export const starUnstarQuery = async (req, res) => {
    try {
        const { id } = req.params;
        const { star } = starQuerySchema.parse(req.body);

        const query = await Query.findByIdAndUpdate(
            id,
            { star },
            { new: true }
        );

        if (!query) {
            return res.status(404).json({
                success: false,
                message: "Query not found"
            });
        }

        res.status(200).json({
            success: true,
            message: `Query ${star ? "starred" : "unstarred"} successfully`,
            data: query
        });

    } catch (err) {
        res.status(400).json({
            success: false,
            message: err.errors?.[0]?.message || err.message
        });
    }
};
