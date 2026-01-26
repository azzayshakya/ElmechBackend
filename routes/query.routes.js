import { authorizeRoles } from "../middlewares/authorize.middleware";
import { protect } from "../middlewares/auth.middleware";
import { listQueries, starUnstarQuery } from "../controllers/query.controller";

router.post("/queries", createQuery);

router.get(
    "/admin/queries",
    protect,
    authorizeRoles("admin", "ceo", "cfo", "cto", "project_manager"),
    listQueries
);

router.patch(
    "/admin/queries/:id/star",
    protect,
    authorizeRoles("admin", "ceo", "cfo", "cto", "project_manager"),
    starUnstarQuery
);
