"use client";

import { useMemo } from "react";

import * as accountsService from "@/services/accounts.service";
import * as runsService from "@/services/runs.service";

export function useApi() {
  return useMemo(
    () => ({
      fetchRunsList: runsService.fetchRunsList,
      fetchAccounts: accountsService.listAccounts,
      fetchRun: runsService.fetchRun,
      fetchRunFinding: runsService.fetchRunFinding,
      fetchRunFindingsCapped: runsService.fetchRunFindingsCapped,
      fetchRunFindings: runsService.fetchRunFindings,
      postCancelRun: runsService.cancelRun,
      postAccountRuns: runsService.enqueueRun,
      registerAccount: accountsService.registerAccount,
      verifyAccount: accountsService.verifyAccount,
      deleteAccount: accountsService.deleteAccount,
    }),
    [],
  );
}

export type { RegisterAccountBody } from "@/services/accounts.service";
