# ディレクトリと責務の境界

実装は適合性テストのプランそのものではなく、OIDC Core・OpenID Federation・
Identityの責務で分けます。Basicなどのプランは同じOIDC処理を利用するため、
プランごとに認可・トークン発行を複製しません。

| ディレクトリ / ファイル | 責務                                                                                 |
| ----------------------- | ------------------------------------------------------------------------------------ |
| `src/index.ts`          | Workerの入口、共通エラー・レスポンスヘッダー                                         |
| `src/config.ts`         | 環境設定の読み込みと検証                                                             |
| `src/provider.ts`       | ルーティングと各コンテキストの組み立て                                               |
| `src/oidc/`             | Discovery、認可、コード・トークン発行、UserInfo、PAR、クライアント認証、クレーム選択 |
| `src/federation/`       | Entity Configuration、信頼チェーン、RPメタデータ、署名付きRequest Objectの検証       |
| `src/identity/`         | パスワードログイン、CSRF、SSOセッション、実際の認証方式                              |
| `src/storage/`          | Durable Objectによる永続化、排他的消費、リプレイ検出と期限切れ削除                   |
| `src/shared/`           | 暗号、HTTP、固定エラー、共通データ型・検証ヘルパー                                   |

## 境界をまたぐ処理

`provider.ts` がFederationとIdentityを組み立て、OIDC処理に渡します。

- OIDCは `oidc/clients.ts` の `FederatedClients` 契約を使い、Federation実装を直接参照しません。
  Federationは署名・信頼・登録情報を検証した `AuthRequest` / RP情報を返します。
  静的クライアントは明示的な登録設定から解決し、URI形式のクライアントを静的登録へ迂回させません。
- 静的クライアントとFederation RPは、同じログイン・コード発行・トークン処理を使います。
  `identity/login.ts` は認証成功時に注入された処理を呼び、OIDCコードやトークンを発行しません。
- OIDCのDiscoveryを基にFederationのEntity Configurationを構築します。
  Federation側の署名付きRequest Object必須制約は維持します。
- `shared/` と `storage/` はOIDC・Federation・Identityの実装に依存させません。
  `shared/types.ts` は現在の小規模PoCで共有する設定・要求・保存データの型です。
  外部向けに独立したサービスを分割する構成ではありません。

Durable Objectの公開クラス名 `ProviderState`、`STATE` バインディング、マイグレーション、
保存キーとデータ形式は維持します。ファイル移動によるデータ移行は不要です。

## テストと公式スイート

- `test/oidc/`: 静的クライアントのCoreフロー、SSO、クライアント認証など。
- `test/federation/`: Federationを入口とする認可・トークン交換の統合テスト。
  共通ログイン・ストレージの保証も含み、内部関数の配置に合わせて分断しません。
- `test/conformance/basic/` / `test/conformance/federation/`: 各プラン固有のCI判定・異常系監査。
- `test/conformance/`: 共通結果処理と日次アップデーターのテスト。
- `scripts/conformance/basic/`: Basicの確認済みモジュールと許可するREVIEW・SKIPPED、判定処理。
- `scripts/conformance/federation/`: Federationの確認済みモジュールと異常系監査。
- `scripts/conformance/` 直下: 共通ランナー、結果出力、日次更新、単一の上流SHA。

`npm test` は `test/**/*.test.mjs` を引用付きでNodeに渡し、サブディレクトリを含む全件を実行します。
公式スイートの実行コマンド、CIマトリクス、成果物の保存先は変更しません。
実行方法は [setup.md](setup.md)、日次更新は [conformance-updates.md](conformance-updates.md) を参照してください。
