import type { Config } from "../shared/types";
import type { Store } from "../storage/state";
import type { FederatedClients } from "../oidc/clients";
import { TrustChain } from "./trust-chain";
import { relyingParty } from "./metadata";
import { request } from "./request-object";
export class Federation implements FederatedClients {
  private chain: TrustChain;
  constructor(
    private config: Config,
    private store: Store,
    signal: AbortSignal,
  ) {
    this.chain = new TrustChain(config, signal);
  }
  relyingParty(id: string) {
    return relyingParty(this.chain, id);
  }
  request(raw: string, id: string) {
    return request(
      this.config,
      this.store,
      (clientId) => this.relyingParty(clientId),
      raw,
      id,
    );
  }
}
