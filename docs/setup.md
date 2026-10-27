# 起動・実行手順

[README](../README.md)

## ローカル開発

Node.js 24 を推奨します。Cloudflare アカウントなしでローカルテストできます。

```bash
npm ci
test -f .dev.vars || npm run setup:local
npm run dev
```

`setup:local` は秘密鍵と開発用アカウントを生成し、Git 管理外の `.dev.vars` に権限 `0600` で保存します。既存ファイルは上書きしません。ログイン情報はそのファイルで手元で確認してください。キーやパスワードをログ・チャット・コミットに貼らないでください。

既定のローカル issuer は `http://localhost:8787`。`DEV_MODE=true` の場合だけ localhost の HTTP issuer を許可します。Federation 文書の取得先は開発時も HTTPS に限定します。

`GET /healthz`、`GET /.well-known/openid-configuration`、`GET /.well-known/openid-federation` で起動を確認できます。信頼アンカー未設定では RP 登録を拒否します。Wrangler のローカル状態は `.wrangler/` に保存され、本番の Durable Objects とは独立しています。

```bash
npm run typecheck
npm test
npm run format:check
```

`npm test` は `npm run build`（Wrangler の dry-run）と統合テストを実行します。デプロイや課金対象リソースの作成は行いません。テストは Miniflare/workerd で Worker と SQLite Durable Objects を実際に動かし、署名付き Federation 文書を模擬します。JAR GET/POST、PAR、JWE、PKCE、ログイン、ID Token、GET/POST UserInfo、不正な署名・クレーム・チェーン・リプレイ・CSRF、再起動後の状態維持、同時コード交換の一度限りの成功を検証します。

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

公開鍵は `/jwks` に出ますが、秘密鍵は公開しません。

`ISSUER` ごとに同じ Durable Object を選び、期限付きレコードをトランザクションで保存・消費します。再起動でリプレイ記録を失わず、同時リクエストが同じコードを二度使うことも防ぎます。期限切れレコードは alarm で掃除します。issuer 変更は別の状態領域になります。

## Federation の設定

`wrangler.jsonc` の `vars` の該当部分を編集します。公開鍵は実際の値を設定してください。

```json
{
  "FEDERATION_HOSTS": "[\"rp.example.com\",\"anchor.example.com\"]",
  "TRUST_ANCHORS": "{\"https://anchor.example.com\":{\"keys\":[...]}}"
}
```

取得先 URL は HTTPS/443 のみ、リダイレクトは追跡せず、文書サイズ・回数・時間に上限を設けています。IP リテラルは共有アドレス空間 `100.64.0.0/10` と IPv4-mapped IPv6 を含めて拒否します。

Workers の Fetch API では DNS の解決先 IP を直接検査してソケットに固定できません。**許可リストには管理者が信頼するホストだけを登録してください。** 任意の未登録ホストの RP を発見・登録する設計ではありません。

## 公式適合性テストの実行

通常の `TypeScript Workers` ジョブとは別に、`Official Federation conformance`
ワークフローを実行します。PR と main への push（文書だけの変更を除く）で
実行し、Actions の **Run workflow** からも手動実行できます。

公開デプロイ、Cloudflare アカウント、GitHub Secrets の追加は不要です。
固定コミットの公式 OpenID Foundation スイートを Java 21 でビルドし、MongoDB と
Miniflare/workerd の Worker を CI 内で起動します。公式プランの全20モジュールを
API から順番に実行し、公式の HtmlUnit ブラウザー操作でログインやエラーページを
処理します。Chromium の独立したブラウザーテストではありません。

`op.teraland.test` と `suite.teraland.test` の HTTPS 接続には、その実行だけの CA と
証明書を生成します。Java の専用 truststore と Node の HTTPS Agent に CA を設定し、
証明書・ホスト名の検証を維持します。DNS 対応付けはテストハーネス内だけで行い、
Worker の署名検証・信頼アンカー検証・ホスト許可リストはそのまま通します。
スイートの開発用認証は loopback 限定のサーバーでのみ使います。

ローカルで同じ実行をする場合:

```bash
# Node.js 24 / 完全な JDK 21（JRE だけでは不可）/ Maven 3.9+ /
# Docker / OpenSSL / Git が必要です。Java の keytool も使います。
npm ci
npm run test:conformance
```

Linux で非特権プロセスが443番へ bind できない場合は、CI と同じ一時環境で
`sudo sysctl -w net.ipv4.ip_unprivileged_port_start=0` を設定してください。
HTTPS は `127.0.0.1:443`、Java サーバーは `127.0.0.1:18080`、MongoDB は動的な
loopback ポートを使います。既存のサービスと競合しない環境で実行してください。

公式スイートは `.local/conformance-suite/` に取得します。
`CONFORMANCE_SUITE_DIR` で既存の checkout を指定できますが、指定された固定 SHA と
一致し、追跡ファイルに変更がない必要があります。固定 SHA とモジュール数は
`scripts/conformance/upstream.json`、CI の checkout SHA は workflow にも記載しています。
更新するときは両方を揃え、実際のプラン構成を再確認してください。

結果は `artifacts/conformance/` に保存し、CI の artifact と Job Summary に残します。
`results.json` はモジュールごとの公式 status/result と集計、`junit.xml` は厳格な適合性
判定の診断用、`summary.md` は人が読む概要です。生成された秘密鍵・認証情報を含み得る
生のスイート設定、ログ、ZIP エクスポートは artifact に含めません。実行用の秘密鍵・
CA・ローカル状態・私用ログと、このスクリプトが起動した MongoDB は終了時に削除します。

**全20件が FINISHED で公式判定が PASSED または REVIEW、かつ異常系13件の応答検証が成功した場合に CI を成功にします。**
ゼロ件、重複、件数不足、未完了、FAILED、WARNING、SKIPPED は引き続き失敗です。
公式判定自体は変更せず、画面確認が必要な REVIEW を PASSED に上書きしません。
異常系では拒否理由・HTTP 400・HTML・リダイレクト／Cookie／フォーム／認可情報の不在・
キャッシュ抑止とページ保護ヘッダーを追加で検証します。jti 再利用では初回の受付も確認します。
検証の詳細は [異常系の検証](conformance-negative.md) を参照してください。

`results.json` の `ciSuccess` は CI 実行ゲート、`success` は全件 PASSED が必要な厳格な
適合性判定です。CI が緑でも `success: false` と REVIEW が残る場合があります。
JUnit は厳格な判定の診断資料なので REVIEW も `failure type="review"` として残ります。
Job Summary と Actions の注記にも件数を表示します。

Provider が不正リクエストをエラーページで拒否する異常系では、公式スイートが人手確認を
要求します。実際のページ内容を確認用 placeholder に記録しても、判定は REVIEW のまま
です。CI 成功を全件合格や認証取得と読み替えず、手動確認は別途行ってください。

## 公開スイートとの接続

案内: <https://openid.net/certification/federation_testing/>

最初の対象プランは `openid-federation-entity-joined-to-test-federation-op-test-plan` です。使用する公式テストコードは [コミット f237360](https://github.com/openid-certification/conformance-suite/tree/f23736032b52739e5262c91263ee102a7bc6ce1a)。その版は alpha / certifiable=false です。

公開 HTTPS issuer を用意し、スイート側の `federation.entity_identifier` に設定します。スイートが公開する trust anchor の identifier と公開鍵を `TRUST_ANCHORS` に、その関連ホストを `FEDERATION_HOSTS` に設定します。RP 自体の issuer、JWKS、anchor の各 endpoint が双方から到達可能である必要があります。スイートのブラウザー操作では `username` / `password` のフォームを使います。
