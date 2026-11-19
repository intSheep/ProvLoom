import type { AccessScopeContext } from "./types";

export interface ApiClientConfig {
  baseUrl?: string;
  getScope: () => AccessScopeContext;
}

export function buildScopeHeaders(scope: AccessScopeContext): Record<string, string> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "X-Tenant-Id": scope.tenantId,
  };
  if (scope.allowedSources?.length) {
    headers["X-Allowed-Sources"] = scope.allowedSources.join(",");
  }
  return headers;
}
