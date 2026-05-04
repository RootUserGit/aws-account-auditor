export function groupKey(pillar: string, severity: string): string {
  return `${pillar}|${severity}`;
}
