import { apiClient } from "@/lib/api/axios-client";
import { apiEndpoints } from "@/lib/api/api-endpoints";

export function fetchRunsList(skip: number, limit: number, accountId?: string) {
  return apiClient.get<unknown>(apiEndpoints.runsList(skip, limit, accountId));
}

export function fetchRun(runId: string) {
  return apiClient.get<unknown>(apiEndpoints.run(runId));
}

export function fetchRunFinding(runId: string, findingId: string) {
  return apiClient.get<unknown>(apiEndpoints.runFinding(runId, findingId));
}

export function fetchRunFindingsCapped(runId: string, limit: number) {
  return apiClient.get<unknown>(apiEndpoints.runFindingsCapped(runId, limit));
}

export function fetchRunFindings(runId: string, params: URLSearchParams) {
  return apiClient.get<unknown>(apiEndpoints.runFindings(runId, params));
}

export function cancelRun(runId: string) {
  return apiClient.post<unknown>(apiEndpoints.cancelRun(runId));
}

export function enqueueRun(platformAccountUuid: string) {
  return apiClient.post<unknown>(apiEndpoints.accountRuns(platformAccountUuid));
}
