# 動的クライアント登録

OIDC Dynamic Client Registrationの登録エンドポイントを、Core Basicのcodeフロー向けに実装しています。
Federationのautomatic registrationとは独立した機能です。

## 有効化

既定は無効です。32文字以上のランダムな初期アクセストークンを
`DYNAMIC_REGISTRATION_TOKEN` に設定すると、Discoveryに `registration_endpoint` が追加されます。
ローカルでは既存の `.dev.vars` に追加し、CloudflareではSecretとして設定します。
トークンをGit管理下の設定やシェル履歴に記載しないでください。

```bash
npx wrangler secret put DYNAMIC_REGISTRATION_TOKEN
```

登録要求は `POST /register`、`Content-Type: application/json`、
`Authorization: Bearer <初期アクセストークン>` で送信します。
issuerにパスがある場合、その配下の `/register` です。
リクエストボディの例：

```json
{
  "redirect_uris": ["https://client.example/callback"],
  "client_name": "PoC client",
  "token_endpoint_auth_method": "client_secret_basic"
}
```

成功時はHTTP 201で `client_id`、`client_secret`、`client_id_issued_at`、
`client_secret_expires_at` と有効な登録メタデータを返します。
レスポンスは `Cache-Control: no-store` です。シークレットはこの応答で受け取り、クライアント側で安全に保存します。
サーバーにはハッシュだけを保存し、取得・更新・削除APIは提供しません。
初期アクセストークンは登録専用で、発行されたクライアントのシークレットとは別です。

## 対応するメタデータ

- HTTPSの完全一致 `redirect_uris` を1〜16件。userinfo・fragmentを含むURIは拒否します。
- `application_type: web`、`response_types: ["code"]`、`subject_type: public`。
- `token_endpoint_auth_method`: `client_secret_basic`（既定）または `client_secret_post`。
  登録した方式だけでトークン交換できます。静的登録の互換動作は変更しません。
- `grant_types`: `authorization_code`。併せて `refresh_token` を要求された場合は、
  対応する `authorization_code` だけを登録・応答します。refresh tokenは発行しません。
- `id_token_signed_response_alg: RS256`（既定）。署名なしID Tokenは登録できません。
- 任意の `client_name`、`contacts`、公開 `jwks`。
- `request_uris` はHTTPSのメタデータとして検証・保存しますが、参照取得は行いません。
  Discoveryの `request_uri_parameter_supported` は引き続きfalseです。

未知の拡張フィールドは無視します。未対応の認証方式・フロー・署名／暗号化要求、
private JWK、`jwks_uri`・`sector_identifier_uri`・software statementなどの未対応メタデータは拒否します。
登録メタデータ中のURIをサーバーから取得することはありません。

登録要求は16 KiBまで、同時に有効な動的クライアントはissuerあたり256件までです。
24時間で登録とシークレットが失効します。上限判定と保存はDurable Objectのトランザクションで行い、
再起動でも登録情報を保持します。上限到達時はHTTP 503 `temporarily_unavailable`、
不正なメタデータはHTTP 400 `invalid_client_metadata` / `invalid_redirect_uri` です。
初期アクセストークンを削除すると、新規登録と動的クライアントの解決を無効化します。
既存の認証中リクエストや発行済みトークンを一括失効する機能ではありません。

## 公式Basicテスト

```bash
CONFORMANCE_PROFILE=basic-dynamic npm run test:conformance
```

公式Basicプランの `discovery + dynamic_client` 構成で38モジュールを実行します。
静的登録35件は別の `basic` 構成として残し、CIは両方を実行します。
動的構成の確認済みモジュールと判定方針は `scripts/conformance/basic/dynamic-profile.json` にあります。

静的構成の3件の手動REVIEWと3件の任意機能SKIPPEDに加え、動的構成では署名なしID Tokenと
署名なしrequest_uriの検査を、非対応機能としてSKIPPEDにすることを許容します。
デフォルトRS256署名の検査は実行します。その他のSKIPPED・REVIEW、WARNING・FAILED・未完了・
モジュールの追加削除は実行ゲートを失敗させます。公式判定をPASSEDへ変更しません。

結果は `artifacts/conformance-basic-dynamic/` に保存します。
CIの初期アクセストークンは毎回生成し、秘密情報を含む生ログ・設定は成果物に含めません。
公開デプロイや公式認定を示すものではありません。
