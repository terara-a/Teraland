# Teraland

Cloudflare Workers 向けの TypeScript 製 OpenID Provider。SQLite-backed Durable Objects で認証状態を管理し、OpenID Federation の OP 自動クライアント登録を対象にしています。

個人 PoC 用です。公式適合性テストの全件合格・認証取得や、本番運用の準備は完了していません。

ローカル起動、設定、Cloudflare へのデプロイ、テストの実行方法は [起動・実行手順](docs/setup.md) を参照してください。

## 実装範囲

- RS256 署名 Entity Configuration、OIDC Discovery、公開 JWKS。
- 固定 trust anchor までのチェーン構築と、各署名・issuer・subject・期限・鍵の結び付けの検証。
- automatic registration、登録済み署名アルゴリズムと redirect URI の適用。
- JAR GET/POST、PAR、private_key_jwt、認可コード、S256 PKCE、RS256 ID Token、GET/POST Bearer UserInfo。
- RS256 / PS256 / ES256 の署名検証。RSA-OAEP-256 / RSA-OAEP + A256GCM の JWE。
- 必須クレーム、禁止された sub、不正署名、リプレイ、信頼期限の検査。
- 要求ごとの CSRF Cookie、Origin 検査、HTML エスケープ、検証済み RP コールバックへの遷移を許可する CSP。

`trust_chain` header 自体は信用せず、ネットワークからチェーンを再構築します。未対応の metadata policy / constraints / critical extension を含むチェーン、未対応の ID Token 署名・暗号化要求は拒否します。

## 未対応

metadata policy の合成、constraints、trust marks、explicit registration、intermediary / trust anchor としての fetch/list/resolve、鍵ローテーション、ユーザー管理、パスワードハッシュ、レート制限、監査・運用監視は未実装です。
