"use client";

import Box from "@cloudscape-design/components/box";
import Button from "@cloudscape-design/components/button";
import ColumnLayout from "@cloudscape-design/components/column-layout";
import Container from "@cloudscape-design/components/container";
import ContentLayout from "@cloudscape-design/components/content-layout";
import Header from "@cloudscape-design/components/header";
import SpaceBetween from "@cloudscape-design/components/space-between";
import Image from "next/image";
import { useRouter } from "next/navigation";

const CARDS = [
  {
    title: "Security first",
    body: "IAM, GuardDuty, KMS, RDS, network exposure, CloudTrail integrity, and data perimeter signals collected with graceful degradation.",
  },
  {
    title: "Cost discipline",
    body: "Cost Explorer, Budgets, Trusted Advisor hooks, and EC2 waste signals (EIPs, detached EBS, stopped fleets).",
  },
  {
    title: "Operator UX",
    body: "Findings stay behind pillar → severity groups with pagination — no wall of JSON until you expand a row.",
  },
] as const;

export default function Home() {
  const router = useRouter();

  return (
    <ContentLayout
      header={
        <Header variant="h1" description="Autonomous audit pipeline">
          Well-Architected security &amp; cost insights
        </Header>
      }
      maxContentWidth={1200}
    >
      <SpaceBetween size="l">
        <Box variant="p" color="text-body-secondary">
          Connect accounts through a read-only cross-account IAM role, execute
          collector-backed checks aligned with CSPM-style posture reviews, and
          review grouped findings with production-grade remediation playbooks —
          deterministic rules stay the source of truth.
        </Box>
        <SpaceBetween direction="horizontal" size="xs">
          <Button variant="primary" onClick={() => router.push("/onboarding")}>
            Onboard account
          </Button>
          <Button onClick={() => router.push("/dashboard")}>
            Open dashboard
          </Button>
        </SpaceBetween>

        <ColumnLayout columns={3} variant="text-grid" minColumnWidth={200}>
          {CARDS.map((card) => (
            <Container
              key={card.title}
              header={<Header variant="h2">{card.title}</Header>}
            >
              <SpaceBetween size="s">
                <Box color="text-body-secondary" fontSize="body-s">
                  {card.body}
                </Box>
                <div className="relative h-12 w-12 opacity-[0.15] pointer-events-none">
                  <Image
                    src="https://a0.awsstatic.com/libra-css/images/logos/aws_logo_smile_1200x630.png"
                    alt=""
                    fill
                    className="object-contain"
                    sizes="48px"
                  />
                </div>
              </SpaceBetween>
            </Container>
          ))}
        </ColumnLayout>

        <Container header={<Header variant="h2">Customer IAM</Header>}>
          <Box variant="p" color="text-body-secondary" fontSize="body-s">
            Ship the template in{" "}
            <Box variant="awsui-inline-code">policies/auditor-policy.json</Box>{" "}
            and trust your platform principal with a scoped{" "}
            <Box variant="awsui-inline-code">sts:ExternalId</Box>. No long-lived
            access keys on analyst workstations.
          </Box>
        </Container>
      </SpaceBetween>
    </ContentLayout>
  );
}
