import { limitedText } from "../shared/http";
import { keySet, verify, unverified } from "../shared/crypto";
import {
  obj,
  str,
  num,
  strings,
  validTimes,
  requireThat,
  type Config,
  type ObjectMap,
} from "../shared/types";
import { identifier } from "./discovery";
import { restrictions } from "./metadata";
export class TrustChain {
  private budget = 24;
  constructor(
    private config: Config,
    private signal: AbortSignal,
  ) {}
  async fetch(uri: string) {
    const u = new URL(uri);
    // Workers cannot pin DNS results to sockets. Only operator-approved DNS hosts
    // are eligible, never IP literals, redirects, arbitrary hosts or ports.
    requireThat(
      u.protocol === "https:" &&
        !u.username &&
        !u.password &&
        !u.hash &&
        (!u.port || u.port === "443") &&
        this.config.hosts.includes(u.hostname) &&
        /^[a-z0-9.-]+$/i.test(u.hostname) &&
        !/^\d+(\.\d+)*$/.test(u.hostname),
      "federation destination not allowed",
    );
    requireThat(this.budget-- > 0, "federation fetch budget exceeded");
    const r = await fetch(u, {
      redirect: "manual",
      signal: this.signal,
      headers: { Accept: "application/entity-statement+jwt, application/json" },
    });
    requireThat(r.status === 200 && r.body, "federation fetch failed");
    return limitedText(r.body);
  }
  async resolve(
    id: string,
    seen = new Set<string>(),
    depth = 0,
  ): Promise<ObjectMap> {
    identifier(id);
    requireThat(depth <= 5 && !seen.has(id), "trust chain depth or cycle");
    seen.add(id);
    try {
      const raw = await this.fetch(id + "/.well-known/openid-federation");
      const leaf = await verify(
        raw,
        keySet(unverified(raw).jwks),
        "entity-statement+jwt",
      );
      requireThat(
        leaf.iss === id && leaf.sub === id,
        "entity identifier mismatch",
      );
      validTimes(leaf, true);
      restrictions(leaf);
      if (this.config.anchors[id]) {
        await verify(raw, this.config.anchors[id], "entity-statement+jwt");
        return leaf;
      }
      const hints = strings(leaf.authority_hints);
      requireThat(hints.length <= 8, "too many authority hints");
      for (const parent of hints) {
        try {
          const superior = await this.resolve(parent, seen, depth + 1);
          const fed = obj(obj(superior.metadata).federation_entity);
          const endpoint = new URL(str(fed, "federation_fetch_endpoint"));
          endpoint.searchParams.set("sub", id);
          endpoint.searchParams.set("iss", parent);
          const statement = await verify(
            await this.fetch(endpoint.href),
            keySet(superior.jwks),
            "entity-statement+jwt",
          );
          requireThat(
            statement.iss === parent && statement.sub === id,
            "subordinate identifier mismatch",
          );
          validTimes(statement, true);
          restrictions(statement);
          await verify(raw, keySet(statement.jwks), "entity-statement+jwt");
          leaf.exp = Math.min(
            num(leaf, "exp"),
            num(superior, "exp"),
            num(statement, "exp"),
          );
          const metadata = obj(leaf.metadata);
          for (const [typ, v] of Object.entries(obj(statement.metadata)))
            metadata[typ] = { ...obj(metadata[typ]), ...obj(v) };
          leaf.metadata = metadata;
          return leaf;
        } catch {
          continue;
        }
      }
      throw new Error("no valid path to a pinned trust anchor");
    } finally {
      seen.delete(id);
    }
  }
}
