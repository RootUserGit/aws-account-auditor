import { apiClient } from "@/lib/api/axios-client";
import { apiEndpoints } from "@/lib/api/api-endpoints";

export type RegisterAccountBody = {
  account_id: string;
  role_arn: string;
  external_id: string;
  display_name: string;
  environment: string;
};

export function listAccounts() {
  return apiClient.get<unknown>(apiEndpoints.accounts());
}

export function listEnvironmentTags() {
  return apiClient.get<unknown>(apiEndpoints.accountEnvironmentTags());
}

export function getAccount(accountRowUuid: string) {
  return apiClient.get<unknown>(apiEndpoints.accountById(accountRowUuid));
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
