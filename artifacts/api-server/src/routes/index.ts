import { Router, type IRouter } from "express";
import healthRouter from "./health";
import blackstarRouter from "./blackstar";

const router: IRouter = Router();

router.use(healthRouter);
router.use(blackstarRouter);

export default router;
