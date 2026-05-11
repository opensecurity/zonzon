import { ServerConfig } from "@opensecurity/zonzon-core";

export interface ConfigContext {
  tenantId: string;
  deviceHash: string;
}

export interface ConfigUpdateResponse {
  success: boolean;
  timestamp: number;
}

export interface ApiAuthHeaders {
  authorization?: string;
  "x-api-key"?: string;
  "x-device-id": string;
  "x-pow-nonce"?: string;
}