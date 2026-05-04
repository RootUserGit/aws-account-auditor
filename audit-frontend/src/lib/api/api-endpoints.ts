export const apiEndpoints = {
  accounts: () => "/api/backend/accounts",

  accountById: (accountRowUuid: string) =>
    `/api/backend/accounts/${encodeURIComponent(accountRowUuid)}`,

  accountVerify: (accountRowUuid: string) =>
    `/api/backend/accounts/${encodeURIComponent(accountRowUuid)}/verify`,

  runsList: (skip: number, limit: number) =>
    `/api/backend/runs?skip=${skip}&limit=${limit}`,

  run: (runId: string) => `/api/backend/runs/${encodeURIComponent(runId)}`,

  runFinding: (runId: string, findingId: string) =>
    `/api/backend/runs/${encodeURIComponent(runId)}/findings/${encodeURIComponent(findingId)}`,

  runFindings: (runId: string, query: URLSearchParams) =>
    `/api/backend/runs/${encodeURIComponent(runId)}/findings?${query}`,

  runFindingsCapped: (runId: string, limit: number) =>
    `/api/backend/runs/${encodeURIComponent(runId)}/findings?limit=${limit}`,

  accountRuns: (platformAccountUuid: string) =>
    `/api/backend/accounts/${encodeURIComponent(platformAccountUuid)}/runs`,

  cancelRun: (runId: string) =>
    `/api/backend/runs/${encodeURIComponent(runId)}/cancel`,

  reportHtml: (runId: string) =>
    `/api/backend/runs/${encodeURIComponent(runId)}/report.html`,

  findingDetail: (runId: string, findingId: string) =>
    `/dashboard/runs/${encodeURIComponent(runId)}/findings/${encodeURIComponent(findingId)}`,
};
