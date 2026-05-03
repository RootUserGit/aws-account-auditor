import { NextRequest, NextResponse } from "next/server";

const base = process.env.AUDIT_API_URL ?? "http://127.0.0.1:8000";
const apiKey = process.env.AUDIT_API_KEY ?? "";

async function forward(
  request: NextRequest,
  pathSegments: string[],
  method: string
) {
  const path = pathSegments.join("/");
  const qs = request.nextUrl.search;
  const target = `${base.replace(/\/$/, "")}/${path}${qs}`;

  const headers: Record<string, string> = {
    "X-API-Key": apiKey,
  };
  const ct = request.headers.get("content-type");
  if (ct) headers["content-type"] = ct;

  let body: BodyInit | undefined;
  if (method !== "GET" && method !== "HEAD") {
    body = await request.arrayBuffer();
  }

  const res = await fetch(target, {
    method,
    headers,
    body,
    cache: "no-store",
  });

  const outHeaders = new Headers();
  const copyCt = res.headers.get("content-type");
  if (copyCt) outHeaders.set("content-type", copyCt);
  const totalCount = res.headers.get("x-total-count");
  if (totalCount) outHeaders.set("X-Total-Count", totalCount);

  return new NextResponse(await res.arrayBuffer(), {
    status: res.status,
    headers: outHeaders,
  });
}

export async function GET(
  request: NextRequest,
  ctx: { params: Promise<{ path: string[] }> }
) {
  const { path } = await ctx.params;
  return forward(request, path, "GET");
}

export async function POST(
  request: NextRequest,
  ctx: { params: Promise<{ path: string[] }> }
) {
  const { path } = await ctx.params;
  return forward(request, path, "POST");
}

export async function DELETE(
  request: NextRequest,
  ctx: { params: Promise<{ path: string[] }> }
) {
  const { path } = await ctx.params;
  return forward(request, path, "DELETE");
}
