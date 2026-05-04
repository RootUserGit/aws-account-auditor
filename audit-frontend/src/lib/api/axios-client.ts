import axios from "axios";

/**
 * Browser client for same-origin `/api/backend/*` proxy. Does not throw on 4xx/5xx
 * (callers check `status` like legacy `fetch` + `res.ok`).
 */
export const apiClient = axios.create({
  validateStatus: () => true,
});
