import { z } from "zod";

export const ApiAuthHeaderSchema = z.object({
  "x-api-key": z.string().min(32).max(128),
  "x-device-id": z.string().min(16).max(64),
  "x-pow-nonce": z.string().min(1).max(64).optional()
});