# Teraland

Go 製の OpenID Provider。まず OpenID Federation の **OP 自動クライアント登録テスト**を対象にした、小さな実装です。OIDF の認証取得済み製品ではありません。公式スイートでの合格はまだ確認していません。

## 起動

Go 1.26 以降が必要です。外部 DB は不要です。

```bash
# 開発用の例。本番では固有の認証情報を安全に注入してください。
export TERALAND_USERNAME=alice
export TERALAND_PASSWORD='local-development-password'
go run ./cmd/teraland -dev
```

既定の待ち受けは `127.0.0.1:8080`、issuer は `http://localhost:8080` です。`GET /healthz`、`GET /.well-known/openid-configuration`、`GET /.well-known/openid-federation` で確認できます。

**信頼アンカー未設定では、Federation による RP 登録はすべて拒否します。** Discovery と鍵の公開だけで RP が信頼されることはありません。

```bash
go run ./cmd/teraland \
  -issuer https://op.example.com \
  -listen 127.0.0.1:8080 \
  -data-dir .local/teraland \
  -trust-anchor https://federation.example.com/anchor \
  -trust-anchor-jwks .local/trust-anchor.jwks.json
```

`-trust-anchor-jwks` は、そのアンカーの**公開鍵だけ**を含む JWKS ファイルです。信頼できる経路で入手した鍵を固定してください。取得した任意の自己署名 Entity Configuration を、そのまま新たな信頼アンカーとして扱ってはいけません。

HTTPS の終端はリバースプロキシで行い、issuer と外部 URL を一致させてください。issuer のパス接頭辞にも対応します。`-dev` は HTTP とプライベート IP への Federation アクセスを許可するため、ローカル開発専用です。通常モードでは外部文書の取得時に private / loopback / link-local IP とリダイレクトを拒否します。外向き HTTP は直接接続し、環境の HTTP proxy 設定は利用しません。

秘密鍵は `.local/teraland/` に初回生成し、再起動後も維持します。ディレクトリを保護・永続化してください。認可コード、PAR、アクセストークン、ログイン要求、リプレイ記録はメモリ上にあり、再起動で失効します。単一プロセスで動かしてください。

## 実装した範囲

- RS256 署名の Entity Configuration（`application/entity-statement+jwt`）、OIDC Discovery、公開 JWKS。
- RP の authority hints から固定した trust anchor までの信頼チェーン構築。各 Entity Configuration と subordinate statement の署名、issuer、subject、有効期限、鍵の結び付きを検証。
- 検証済み RP metadata による automatic registration。Federation 用鍵と OIDC クライアント用鍵を分離。
- GET / POST の JAR、PAR、`private_key_jwt`、認可コード、S256 PKCE、ID Token、Bearer UserInfo。
- JWS: RS256 / PS256 / ES256 のリクエスト検証。JWE: RSA-OAEP-256 / RSA-OAEP + A256GCM の署名付きリクエスト復号。
- request object の必須 `iss` / `aud` / `exp` / `jti`、`client_id` の一致、禁止された `sub`、登録済み redirect URI、署名、期限、リプレイを検証。
- ログイン画面と明示的な許可。CSRF Cookie、Origin 検査、HTML エスケープ、CSP、トークン応答のキャッシュ抑止。

`trust_chain` JWS header を含むリクエストも受理しますが、ヘッダーのチェーンを信頼根拠にせず、ネットワークからチェーンを独立に再構築します。独自の policy / constraints / critical extension は未実装で、存在するチェーンは安全側に拒否します。

## 適合性テスト

対象の案内: <https://openid.net/certification/federation_testing/>

初期ターゲットは公式スイートの以下のプランです。

```text
openid-federation-entity-joined-to-test-federation-op-test-plan
```

実装時には公式リポジトリのコミット `f23736032b52739e5262c91263ee102a7bc6ce1a` のテストコードを参照しました。

- [OP test plan](https://github.com/openid-certification/conformance-suite/blob/f23736032b52739e5262c91263ee102a7bc6ce1a/src/main/java/net/openid/conformance/openid/federation/OpenIDFederationClientRegistrationOPTestPlan.java)
- [Deployed entity test plan](https://github.com/openid-certification/conformance-suite/blob/f23736032b52739e5262c91263ee102a7bc6ce1a/src/main/java/net/openid/conformance/openid/federation/OpenIDFederationDeployedEntityTestPlan.java)

この版の両プランは `alpha`、`certifiable = false` です。公開スイートの版・提供状況は別途確認してください。

### 公式スイートにつなぐ手順

1. Teraland を、スイートから到達できる、有効な証明書を持つ HTTPS issuer で起動する。スイート自身の Federation endpoint も Teraland から到達できる必要があります。
2. OP プランを作成し、`federation.entity_identifier` に Teraland の issuer を指定する。`client_registration=automatic` と discovery による metadata 取得を選び、スイートが必要とする RP 用鍵・trust anchor 用鍵を設定する。
3. 構成されたテストが公開する trust anchor の entity identifier と、それに対応する公開 JWKS を確認する。その identifier と JWKS を上記の CLI オプションに設定して Teraland を再起動する。テスト・alias が変わった場合は一致を再確認する。
4. 正常系のブラウザー操作では、`username`、`password` を入力してログイン・許可する。自動ブラウザー操作を使う場合もこのフォームに合わせる。
5. 異常系は JSON の HTTP 400 応答を表示する場合があります。未検証の redirect URI へは転送しません。スイートが画面の確認を求めるケースでは、エラー画面の証跡を登録する。
6. プランを実行し、その実行結果を保存する。下記ローカルテストの成功を、公式テストの合格として扱わない。

**今回、公式スイートのプラン実行は行っていません。** 公開 HTTPS issuer、スイートの trust anchor 設定、ブラウザー操作を含む実環境の接続は未検証です。案内ページは作業環境のアクセス制限で取得できなかったため、取得できた公式テストコードに基づいています。

### ローカルでの検証

```bash
go test -race -count=1 ./...
go vet ./...
go build -o .local/bin/teraland ./cmd/teraland
```

テストは実際の HTTP サーバーで RP と trust anchor を模擬し、署名付き Federation 文書を取得するところから、ログイン、コード交換、ID Token の署名検証、UserInfo まで実行します。GET / POST JAR、PAR、両方の JWE アルゴリズム、PKCE と、署名・クレーム・チェーン・リプレイ・CSRF の拒否を検証します。GitHub Actions にも race test / vet / build を登録しています。

## 今後の範囲

これはテスト接続用の最初の実装です。metadata policy の合成、constraints、trust marks、explicit registration、fetch / list / resolve を提供する intermediary / trust anchor の役割、鍵ローテーションは未実装です。Deployed entity プラン全体への適合も未確認です。

ユーザー認証は環境変数で設定する単一アカウントです。実運用にはユーザー管理、パスワードハッシュ、レート制限・監査、共有永続ストア、セッション管理、鍵ローテーションなどを追加する必要があります。現時点で実ユーザー向けの認証基盤として公開しないでください。
