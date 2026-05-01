import { expect, test } from "@playwright/test";

test("home shows product title", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: /Well-Architected/i })).toBeVisible();
});

test("onboarding page loads", async ({ page }) => {
  await page.goto("/onboarding");
  await expect(page.getByRole("heading", { name: /Onboard AWS account/i })).toBeVisible();
});
