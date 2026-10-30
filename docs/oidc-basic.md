# OIDC Core Basic

[起動・実行手順](setup.md)

Federation の自動登録に加え、管理者が事前登録したクライアントで通常の認可コードフローを利用できます。
単一のPoC用アカウントを使用します。サインアップやユーザーDBはありません。

## クライアントの設定

`STATIC_CLIENTS` を JSON 配列として設定します。ローカルでは既存の `.dev.vars` に追記し、
Cloudflare では `npx wrangler secret put STATIC_CLIENTS` で登録してください。
クライアントシークレットを `wrangler.jsonc` の vars や Git に保存しないでください。

```json
[
  {
    "client_id": "my-app",
    "client_secret": "<ランダム生成した32文字以上の値>",
    "redirect_uris": ["https://app.example.com/callback"]
  }
]
```

例のシークレットを実際の値に置き換えてください。IDは英数字・ハイフン・アンダースコアのみで、
HTTPSのFederation entity identifierとは区別します。コールバックはHTTPSの完全一致で、
queryも一致させます。fragment、HTTP、ワイルドカード、未知の設定項目は拒否します。
既定は未設定（無効）です。既存のFederation RPには引き続き署名・信頼チェーン検証が必要です。

登録した各クライアントは `client_secret_basic` と `client_secret_post` を使用できます。
認証方式の混在、認証情報のquery渡し、不一致のclient_idは拒否します。
動的クライアント登録、public client、client_secret_jwtは未対応です。

## ユーザークレームとセッション

`USER_CLAIMS` にはPoCアカウントの標準クレームをJSONオブジェクトで設定できます。
個人情報を含むため本番では `npx wrangler secret put USER_CLAIMS` を使ってください。
省略時は追加クレームを返しません。実在しない属性を自動生成することはありません。

```json
{
  "name": "Example User",
  "email": "user@example.com",
  "email_verified": false
}
```

`profile`・`email`・`address`・`phone` のスコープと `claims` パラメーターに応じて、
設定済みの属性だけを返します。ID TokenとUserInfoは要求先を区別します。
`sub`・`iss`・`aud`などの保護されたクレームは設定で上書きできません。
UserInfoはBearerヘッダーとPOSTフォーム本文の `access_token` に対応し、両方の併用は拒否します。

パスワード認証のACRは `urn:teraland:acr:password`、AMRは `pwd` です。
必須のACR要求をこの方式で満たせなければ拒否します。MFAを実施したとは主張しません。

事前登録クライアントのログイン成功時だけ、1時間のサーバー管理セッションを発行します。
CookieはHttpOnly・SameSite=Laxで、HTTPSではSecureを付けます。
`prompt=none` は有効なセッションがある場合だけ成功し、`id_token_hint` 単独では認証しません。
`prompt=login`、`max_age=0`、古い認証に対する `max_age` は再ログインを要求します。
認証時刻はセッション再利用時に維持します。ログアウト・セッション管理UIは未実装です。

認可コードは60秒、アクセストークンは5分で失効します。コードは一度だけ消費でき、
同じクライアントの認証済みコード再利用を検出した場合は関連アクセストークンも失効させます。
これらの更新はSQLite Durable Objectsのトランザクションで処理します。

## 公式Basicプランの実行

Federationと同じ固定SHAの公式スイートを使用します。前提ソフトウェア・ローカルHTTPSの
詳細は [起動・実行手順](setup.md#公式適合性テストの実行) を参照してください。

```bash
CONFORMANCE_PROFILE=basic npm run test:conformance
```

プランは `oidcc-basic-certification-test-plan`、discovery＋static_client構成です。
公式プラン自身が固定するcodeフロー・client_secret_basic／postのvariantをそのまま使います。
この構成で適用される35モジュールをすべて実行します。動的登録専用の3モジュールは、
公式のvariant選択によってこの構成の対象から外れます。
CIではFederationの60通りとは別の `official-oidc-basic` ジョブで実行し、日次更新PRも両方を検証します。

確認済みのモジュール名と判定方針は `scripts/conformance/basic.json` にあります。
以下だけをCIで非ブロッキングとし、公式判定は変更しません。

| 公式判定 | 対象                                                                  |
| -------- | --------------------------------------------------------------------- |
| REVIEW   | prompt=login、max_age=1の再ログイン画面、未登録redirect_uriの拒否画面 |
| SKIPPED  | 未対応のrefresh token、署名なしRequest Objectの2検査                  |

他のREVIEW／SKIPPED、WARNING、FAILED、未完了、重複、件数やテスト名の変更はCIを失敗させます。
任意機能のスキップをPASSEDに数えません。`success` は全件PASSED、`ciSuccess` は上記方針で別に判定します。
JUnitにもREVIEW・SKIPPEDを厳格な診断情報として残します。

結果は `artifacts/conformance-basic/` に保存します。RPシークレット、ユーザー認証情報、
署名付きリクエストやトークンの本文、生のJavaログは成果物に含めません。
ローカルでの実行は認証取得ではなく、公開環境や公式認証手続きは別途必要です。
