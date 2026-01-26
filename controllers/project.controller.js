


export const createProject = async (req, res) => {
    try {
        const data = createProjectSchema.parse(req.body);

        if (data.endDate && data.endDate < data.startDate) {
            return res.status(400).json({
                success: false,
                message: "End date cannot be before start date"
            });
        }

        const project = await Project.create({
            ...data,
            created_by: req.user._id
        });

        res.status(201).json({
            success: true,
            message: "Project created successfully",
            data: project
        });

    } catch (err) {
        res.status(400).json({
            success: false,
            message: err.errors?.[0]?.message || err.message
        });
    }
};


export const updateProject = async (req, res) => {
    try {
        const { id } = req.params;
        const data = updateProjectSchema.parse(req.body);

        if (data.startDate && data.endDate && data.endDate < data.startDate) {
            return res.status(400).json({
                success: false,
                message: "End date cannot be before start date"
            });
        }

        const project = await Project.findByIdAndUpdate(
            id,
            {
                ...data,
                $push: {
                    update_history: {
                        updated_by: req.user._id,
                        updated_at: new Date(),
                        field: "project_update",
                        new_value: data
                    }
                }
            },
            { new: true }
        );

        if (!project) {
            return res.status(404).json({
                success: false,
                message: "Project not found"
            });
        }

        res.status(200).json({
            success: true,
            message: "Project updated successfully",
            data: project
        });

    } catch (err) {
        res.status(400).json({
            success: false,
            message: err.errors?.[0]?.message || err.message
        });
    }
};


export const listProjects = async (req, res) => {
    try {
        const params = listProjectSchema.parse(req.query);

        const {
            page,
            limit,
            status,
            department,
            name,
            order
        } = params;

        const filter = {};

        if (status) {
            filter.projectStatus = status;
        }

        if (department) {
            filter.services = department;
        }

        if (name) {
            filter.projectName = { $regex: name, $options: "i" };
        }

        const skip = (page - 1) * limit;
        const sortOrder = order === "asc" ? 1 : -1;

        const [projects, total] = await Promise.all([
            Project.find(filter)
                .sort({ created_at: sortOrder })
                .skip(skip)
                .limit(limit)
                .populate("created_by", "name email"),
            Project.countDocuments(filter)
        ]);

        res.status(200).json({
            success: true,
            data: projects,
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