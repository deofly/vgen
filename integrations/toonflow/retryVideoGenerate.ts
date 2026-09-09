import express from "express";
import { success, error } from "@/lib/responseFormat";
import { validateFields } from "@/middleware/middleware";
import { retryVgenVideo } from "@/utils/vgenRecovery";
import { z } from "zod";
const router = express.Router();
export default router.post(
  "/",
  validateFields({ id: z.number().int().positive() }),
  async (req, res) => {
    if (!retryVgenVideo(req.body.id)) return res.status(409).send(error("没有可重试的 VGen 视频任务"));
    res.status(200).send(success({ id: req.body.id, state: "重新排队" }));
  },
);
