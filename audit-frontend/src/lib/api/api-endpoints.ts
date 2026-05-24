export const apiEndpoints = {
  accounts: () => "/api/backend/accounts",

  accountEnvironmentTags: () =>
    "/api/backend/accounts/meta/environment-tags",

  accountById: (accountRowUuid: string) =>
    `/api/backend/accounts/${encodeURIComponent(accountRowUuid)}`,

  accountVerify: (accountRowUuid: string) =>
    `/api/backend/accounts/${encodeURIComponent(accountRowUuid)}/verify`,

  runsList: (skip: number, limit: number, accountId?: string) => {
    const q = new URLSearchParams({
      skip: String(skip),
      limit: String(limit),
    });
    if (accountId) q.set("account_id", accountId);
    return `/api/backend/runs?${q}`;
  },

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
