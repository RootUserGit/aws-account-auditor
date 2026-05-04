export function parseApiDetail(raw: unknown): string {
  if (typeof raw === "string") return raw;
  if (
    raw &&
    typeof raw === "object" &&
    "message" in raw &&
    typeof (raw as { message: unknown }).message === "string"
  ) {
    return (raw as { message: string }).message;
  }
  return "Request failed";
}
