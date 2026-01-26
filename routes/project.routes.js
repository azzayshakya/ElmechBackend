import { PROJECT_ADMIN_ROLES } from "../validators/project.validator";
import { protect } from "../middlewares/auth.middleware";
import { createProject, updateProject, listProjects } from "../controllers/project.controller";

router.post(
    "/projects",
    protect,
    authorizeRoles(...PROJECT_ADMIN_ROLES),
    createProject
);

router.patch(
    "/projects/:id",
    protect,
    authorizeRoles(...PROJECT_ADMIN_ROLES),
    updateProject
);

router.get(
    "/projects",
    protect,
    authorizeRoles(...PROJECT_ADMIN_ROLES),
    listProjects
);
