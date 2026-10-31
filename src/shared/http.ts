import { requireThat } from "./types";
export async function limitedText(body: ReadableStream<Uint8Array> | null) {
  if (!body) return "";
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      requireThat(size <= 1048576, "document too large");
      chunks.push(value);
    }
  } finally {
    await reader.cancel();
  }
  const bytes = new Uint8Array(size);
  let i = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, i);
    i += chunk.length;
  }
  return new TextDecoder().decode(bytes);
}

export async function form(r: Request) {
  const p = new URL(r.url).searchParams;
  requireThat(["GET", "POST"].includes(r.method), "invalid method");
  if (r.method === "POST") {
    requireThat(
      r.headers.get("content-type")?.split(";")[0].trim() ===
        "application/x-www-form-urlencoded",
      "invalid form type",
    );
    const body = await limitedText(r.body);
    for (const [k, v] of new URLSearchParams(body)) p.append(k, v);
  }
  for (const k of p.keys())
    requireThat(p.getAll(k).length === 1, "duplicate parameter");
  return p;
}

export const policy =
  "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";
export const json = (v: unknown, status = 200) => Response.json(v, { status });
export const fail = (code: string, status = 400) =>
  json({ error: code }, status);
export const escape = (s: string) =>
  s.replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ]!,
  );
