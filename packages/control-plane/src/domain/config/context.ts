import { AsyncLocalStorage } from "node:async_hooks";
import { ConfigContext } from "./config.types.js";

export const contextStorage = new AsyncLocalStorage<ConfigContext>();

export function getContext(): ConfigContext {
  const store = contextStorage.getStore();
  if (!store) {
    throw new Error("Security Exception: Context missing. Ensure request is wrapped in middleware.");
  }
  return store;
}