# Federation 異常系の検証

[起動・実行手順](setup.md#公式適合性テストの実行)

固定した公式プランの異常系13件について、公式 status/result とは独立した応答検証を行います。
人手による画面確認や公式の REVIEW 承認を代行するものではありません。

## 期待する拒否理由

以下のモジュール名には、共通の接頭辞
`openid-federation-automatic-client-registration-` を省略しています。

| モジュール                                          | エラーページの reason |
| --------------------------------------------------- | --------------------- |
| invalid-client-id-in-request-object                 | invalid_iss           |
| invalid-client-id-in-query-parameters               | invalid_client_id     |
| invalid-signature-on-request-object                 | invalid_signature     |
| invalid-signature-with-other-keys-on-request-object | invalid_signature     |
| invalid-request-object-exp                          | invalid_exp           |
| invalid-request-object-iss                          | invalid_iss           |
| invalid-request-object-aud                          | invalid_aud           |
| invalid-request-object-sub                          | forbidden_sub         |
| invalid-missing-request-object-jti                  | invalid_jti           |
| invalid-missing-request-object-exp                  | invalid_exp           |
| invalid-missing-request-object-iss                  | invalid_iss           |
| invalid-missing-request-object-aud                  | invalid_aud           |
| invalid-duplicate-request-object-jti                | replayed_jti          |

公式の invalid-client-id-in-request-object は外側の client_id にも変更値をコピーするため、
元の iss と client_id の不一致として拒否されます。署名異常の2件は typ を省略します。
Request Object の typ は省略可能とし、指定された場合は JWT または oauth-authz-req+jwt のみ許可します。

## 応答と CI 判定

不正な認可要求は、外部へリダイレクトせず、固定の説明文を持つ HTTP 400 の HTML ページで
拒否します。未検証の redirect_uri、state、JWT や例外メッセージは表示しません。
ログイン用フォーム・Cookie・認可コード・トークンも返しません。
PAR は引き続き JSON の `invalid_request_object` を返します。

テストハーネスは実際の `/authorize` 応答を調べ、期待する reason に加え、
Content-Type、Location／Set-Cookie／フォーム／認可情報の不在、Cache-Control、
CSP、Referrer-Policy、X-Content-Type-Options を検証します。
通常の異常系は1応答、jti 再利用は初回 HTTP 200 と再利用時 HTTP 400 の2応答が必要です。
13件のいずれかが欠ける・重複する・期待と異なる場合は CI を失敗させます。

`results.json` の各異常系に `negativeCheck`（期待理由・応答の検証値・verified）、
全体に `negativeChecksSuccess` を記録します。保存するのは固定の理由名・数値・真偽値のみで、
要求や応答の本文、URL、Cookie、鍵、トークン、認証情報は成果物に含めません。
`summary.md` と Job Summary にも検証成功件数を表示します。

`ciSuccess` は公式テストの実行ゲートと異常系検証の両方が成功した場合だけ true になります。
公式 status/result、全件 PASSED を必要とする `success`、厳格な診断用 JUnit は変更しません。
公式の REVIEW が残っている場合は、実際の画面の人手確認が引き続き必要です。

`npm test` では Miniflare/workerd 上で13シナリオを GET／POST の両方から実行し、
拒否応答と PAR の JSON 応答を確認します。公式スイートの実行は別途
`npm run test:conformance` を使ってください。
