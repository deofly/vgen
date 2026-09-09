import express from "express";
import { success, error } from "@/lib/responseFormat";
import { validateFields } from "@/middleware/middleware";
import { cancelVgenVideo } from "@/utils/vgenRecovery";
import { z } from "zod";

const router = express.Router();

/** Cancel only the VGen task correlated with this Toonflow video record. */
export default router.post(
  "/",
  validateFields({ id: z.number().int().positive() }),
  async (req, res) => {
    try {
      const cancelled = await cancelVgenVideo(req.body.id);
      if (!cancelled) return res.status(409).send(error("没有可取消的 VGen 视频任务"));
      res.status(200).send(success({ id: req.body.id, state: "已取消" }));
    } catch (exception) {
      console.error("VGen video cancellation failed", exception instanceof Error ? exception.message : "unknown");
      res.status(409).send(error("远端任务当前无法取消，请用 vgen task show 核对状态"));
    }
  },
);
