import { apiClient } from "@/lib/api/axios-client";
import { apiEndpoints } from "@/lib/api/api-endpoints";

export type RegisterAccountBody = {
  account_id: string;
  role_arn: string;
  external_id: string;
};

export function listAccounts() {
  return apiClient.get<unknown>(apiEndpoints.accounts());
}

export function registerAccount(body: RegisterAccountBody) {
  return apiClient.post<unknown>(apiEndpoints.accounts(), body);
}

export function verifyAccount(accountRowUuid: string) {
  return apiClient.post<unknown>(apiEndpoints.accountVerify(accountRowUuid));
}

export function deleteAccount(accountRowUuid: string) {
  return apiClient.delete<unknown>(apiEndpoints.accountById(accountRowUuid));
}
