import { z } from "zod";

export const ApiAuthHeaderSchema = z.object({
  authorization: z.string().regex(/^Bearer [a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+$/).optional(),
  "x-api-key": z.string().min(32).max(128).optional(),
  "x-device-id": z.string().min(16).max(64),
  "x-pow-nonce": z.string().min(1).max(64).optional()
}).refine(data => data.authorization || data["x-api-key"], {
  message: "Missing authentication credentials",
  path: ["x-api-key"]
});