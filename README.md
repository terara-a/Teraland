# Teraland

Cloudflare Workers 向けの TypeScript 製 OpenID Provider。OpenID Federation の OP 自動クライアント登録テストを最初の目標にしています。Go 版を移植し、認可コード・PAR・ログイン・アクセストークン・リプレイ記録を SQLite-backed Durable Objects に移しました。

**公式適合性テストの合格は未確認です。個人 PoC 用であり、実ユーザーの認証基盤としての準備は完了していません。**

## ローカル開発

Node.js 24 を推奨します。Cloudflare アカウントなしでローカルテストできます。

```bash
npm ci
npm run setup:local
npm run dev
```

`setup:local` は秘密鍵と開発用アカウントを生成し、Git 管理外の `.dev.vars` に権限 `0600` で保存します。既存ファイルは上書きしません。ログイン情報はそのファイルで手元で確認してください。キーやパスワードをログ・チャット・コミットに貼らないでください。

既定のローカル issuer は `http://localhost:8787`。`DEV_MODE=true` の場合だけ localhost の HTTP issuer を許可します。Federation 文書の取得先は開発時も HTTPS に限定します。

`GET /healthz`、`GET /.well-known/openid-configuration`、`GET /.well-known/openid-federation` で起動を確認できます。信頼アンカー未設定では RP 登録を拒否します。Wrangler のローカル状態は `.wrangler/` に保存され、本番の Durable Objects とは独立しています。

```bash
npm run typecheck
npm test
npm run format:check
npm run build
```

`build` は Wrangler の dry-run です。デプロイや課金対象リソースの作成は行いません。テストは Miniflare/workerd で Worker と SQLite Durable Objects を実際に動かし、署名付き Federation 文書を模擬します。JAR GET/POST、PAR、JWE、PKCE、ログイン、ID Token、GET/POST UserInfo、不正な署名・クレーム・チェーン・リプレイ・CSRF、再起動後の状態維持、同時コード交換の一度限りの成功を検証します。

## Cloudflare へのデプロイ

このリポジトリからの本番デプロイはまだ実行していません。Workers と SQLite Durable Objects を使います。無料プランの提供条件・利用上限は申込時に確認してください。無料枠内の利用を保証する構成ではありません。

1. `npx wrangler login` で自分のアカウントにログインする。
2. `wrangler.jsonc` の `ISSUER` を実際の Workers 公開 HTTPS URL に変更する。末尾の `/`、query、fragment は付けない。`name` も必要に応じて変更する。
3. `FEDERATION_HOSTS` に RP、trust anchor、intermediary、JWKS endpoint が使うホスト名を JSON 配列文字列で設定する。完全一致・小文字の DNS ホスト名だけを許可し、ワイルドカードや IP リテラルは許可しない。
4. `TRUST_ANCHORS` を、entity identifier をキー、公開 JWKS を値とする JSON オブジェクト文字列に設定する。鍵は信頼できる別経路で確認したものだけを固定する。
5. 下記の4個の Secrets を設定する。
6. `npm run deploy` を実行し、公開 URL の health/discovery/entity configuration を確認する。

```bash
npx wrangler secret put SIGNING_JWK
npx wrangler secret put ENCRYPTION_JWK
npx wrangler secret put TERALAND_USERNAME
npx wrangler secret put TERALAND_PASSWORD
```

- `SIGNING_JWK`: 秘密鍵を含む RSA 2048 bit 以上の JWK JSON。`kid`、`use: "sig"`、`alg: "RS256"` を設定。
- `ENCRYPTION_JWK`: 署名鍵と異なる RSA 秘密 JWK JSON。固有の `kid` と `use: "enc"` を設定。両方の OAEP アルゴリズムで使うため `alg` は省略。
- `TERALAND_USERNAME`: PoC 用単一アカウント。
- `TERALAND_PASSWORD`: 12文字以上の固有のパスワード。

公開鍵は `/jwks` に出ますが、秘密鍵は公開しません。既存 Go 版から同じ issuer で移行する場合、`.local/teraland/signing.jwk` と `encryption.jwk` は同じ JWK 形式なので Secrets に移せます。既存鍵を失効させる意図がなければ作り直さないでください。Go 版のメモリ上にあった一時状態は移行できません。

`ISSUER` ごとに同じ Durable Object を選び、期限付きレコードをトランザクションで保存・消費します。再起動でリプレイ記録を失わず、同時リクエストが同じコードを二度使うことも防ぎます。期限切れレコードは alarm で掃除します。issuer 変更は別の状態領域になります。

## Federation の設定例

`wrangler.jsonc` の `vars` の該当部分を編集します。公開鍵は実際の値を設定してください。

```json
{
  "FEDERATION_HOSTS": "[\"rp.example.com\",\"anchor.example.com\"]",
  "TRUST_ANCHORS": "{\"https://anchor.example.com\":{\"keys\":[...]}}"
}
```

取得先 URL は HTTPS/443 のみ、リダイレクトは追跡せず、文書サイズ・回数・時間に上限を設けています。IP リテラルは共有アドレス空間 `100.64.0.0/10` と IPv4-mapped IPv6 を含めて拒否します。

Workers の Fetch API では DNS の解決先 IP を直接検査してソケットに固定できません。**許可リストには管理者が信頼するホストだけを登録してください。** この制限は Go 版の DNS/IP 検査と異なります。任意の未登録ホストの RP を発見・登録する設計ではありません。

## 実装範囲

- RS256 署名 Entity Configuration、OIDC Discovery、公開 JWKS。
- 固定 trust anchor までのチェーン構築と、各署名・issuer・subject・期限・鍵の結び付けの検証。
- automatic registration、登録済み署名アルゴリズムと redirect URI の適用。
- JAR GET/POST、PAR、private_key_jwt、認可コード、S256 PKCE、RS256 ID Token、GET/POST Bearer UserInfo。
- RS256 / PS256 / ES256 の署名検証。RSA-OAEP-256 / RSA-OAEP + A256GCM の JWE。
- 必須クレーム、禁止された sub、不正署名、リプレイ、信頼期限の検査。
- 要求ごとの CSRF Cookie、Origin 検査、HTML エスケープ、検証済み RP コールバックへの遷移を許可する CSP。

`trust_chain` header 自体は信用せず、ネットワークからチェーンを再構築します。未対応の metadata policy / constraints / critical extension を含むチェーン、未対応の ID Token 署名・暗号化要求は拒否します。

## 公式適合性テスト

案内: <https://openid.net/certification/federation_testing/>

最初の対象プランは `openid-federation-entity-joined-to-test-federation-op-test-plan` です。参照した公式テストコードは [コミット f237360](https://github.com/openid-certification/conformance-suite/tree/f23736032b52739e5262c91263ee102a7bc6ce1a)。その版は alpha / certifiable=false です。

公開 HTTPS issuer を用意し、スイート側の `federation.entity_identifier` に設定します。スイートが公開する trust anchor の identifier と公開鍵を `TRUST_ANCHORS` に、その関連ホストを `FEDERATION_HOSTS` に設定します。RP 自体の issuer、JWKS、anchor の各 endpoint が双方から到達可能である必要があります。スイートのブラウザー操作では `username` / `password` のフォームを使います。

**ローカルテストの成功を公式スイートの合格と読み替えないでください。** 公開 Cloudflare 上での動作・スイート接続は未検証です。

## 未対応

metadata policy の合成、constraints、trust marks、explicit registration、intermediary / trust anchor としての fetch/list/resolve、鍵ローテーション、ユーザー管理、パスワードハッシュ、レート制限、監査・運用監視は未実装です。Go サーバーの graceful shutdown は Workers のプラットフォーム管理に置き換わりました。Go のファイル・メモリ保存方式は使用しません。
