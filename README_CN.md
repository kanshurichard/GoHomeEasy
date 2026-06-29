# GoHomeEasy

GoHomeEasy v2 用来接收 Lucky Webhook，按 `ruleName` 保存多条记录，再按请求实时生成 Shadowsocks 或 Clash 订阅。

支持的部署方式：

- Cloudflare Workers + KV
- AWS Lambda + DynamoDB
- Go 自托管
- Python 自托管（`gohomeeasy.py` + `dashboard.html`）

## v2 行为

- `ruleName` 必填，会先 `trim`，大小写敏感，最大 128 字节 UTF-8。
- 重复 `ruleName` 不是报错，而是更新同名记录。
- 记录类型只支持 `ss` 和 `site`。
- 不传 `type` 时默认按 `ss` 处理。
- `type=site` 必须显式声明，而且不能带 `method`、`password`。
- 只有 `ss` 记录会进入订阅；`site` 只在 Dashboard 里展示。
- 如果还没有任何 v2 `ss` 记录，系统会继续返回旧版 legacy 订阅内容。
- Cloudflare KV 和 DynamoDB GSI 读都是最终一致的，写入或删除后短时间内 `/subscription`、`/dashboard`、`/api/records` 可能读到旧值。

## 路由

| 路由 | 方法 | 作用 |
| :--- | :--- | :--- |
| `/` | `POST` | Lucky Webhook |
| `/webhook` | `POST` | `/` 的别名 |
| `/?api_key=...` | `GET` | 旧订阅入口；未传 `subtype` 时继续遵守 `SUBSCRIPTION_FORMAT` |
| `/subscription?subtype=ss|clash&api_key=...` | `GET` | 显式订阅入口 |
| `/dashboard?api_key=...` | `GET` | 用 token 换签名 cookie，然后跳转到干净的 `/dashboard` |
| `/api/records` | `GET` | Dashboard 数据接口 |
| `/api/delete` | `POST` | 按 `ruleName` 删除记录 |
| `/healthz` | `GET` | 健康检查 |

规则：

- 两个订阅入口都支持 `Authorization: Bearer READ_TOKEN`，并且优先级高于 `?api_key=`。
- `?api_key=` 只在 `/`、`/subscription`、`/dashboard` 生效。
- `/api/*` 永远忽略 query token。
- `/api/records` 支持 read/write cookie，或 `Authorization: Bearer READ_TOKEN|WRITE_TOKEN`。
- `/api/delete` 支持 `Authorization: Bearer WRITE_TOKEN`，或者 write-mode cookie + 同源 `Origin`。
- 如果没配 `SESSION_SECRET`，`/dashboard` 和 `/api/*` 会返回 `500 dashboard not configured`。

## Webhook 请求体规则

- 地址优先级固定为 `ip` -> `host` -> `server`。
- 一旦某个非空地址字段被选中，但值非法，就直接 `400`，不会继续 fallback。
- 只有当 `ip`、`host`、`server` 都为空时，才会使用 `ipAddr`。
- `ipAddr` 必须是 `host:port` 或 `[ipv6]:port`；使用 `ipAddr` 时会忽略独立 `port` 字段。
- `time` 如果存在，会原样写入 `sourceTime`。
- Lucky Webhook 只负责 upsert；改名和删除需要手工处理。

Shadowsocks 记录示例：

```json
{
  "ruleName": "Home-SS",
  "ip": "#{ip}",
  "port": "#{port}",
  "method": "chacha20-ietf-poly1305",
  "password": "replace-with-password"
}
```

Site 记录示例：

```json
{
  "ruleName": "Home-NAS",
  "type": "site",
  "host": "nas.example.com",
  "port": 443,
  "time": "#{time}"
}
```

## Webhook 必填字段

| 记录类型 | 必填字段 | 可选字段 | 说明 |
| :--- | :--- | :--- | :--- |
| `ss` | `ruleName`、一组地址来源、`method`、`password` | `type`、`time` | `type` 可以不传，默认就是 `ss` |
| `site` | `ruleName`、`type=site`、一组地址来源 | `time` | 不能带 `method`、`password` |

地址来源四选一：

- `ip` + `port`
- `host` + `port`
- `server` + `port`
- `ipAddr`，格式必须是 `host:port` 或 `[ipv6]:port`

补充说明：

- 想更新已有记录时，直接复用同一个 `ruleName`
- 想只在 Dashboard 展示时，显式传 `type=site`
- 想在 Dashboard 里保留 Lucky 原始时间时，再附带 `time`

## 配置项

| 变量 | 必填 | 作用 |
| :--- | :--- | :--- |
| `READ_TOKEN` | 是 | 订阅读取和只读 Dashboard 登录 |
| `WRITE_TOKEN` | 是 | Lucky Webhook 写入和删除操作 |
| `SESSION_SECRET` | Dashboard/API 必填 | 用来签名 Dashboard cookie 的 HMAC 密钥 |
| `SESSION_TTL_SECONDS` | 否 | Dashboard cookie 有效期，默认 `86400` |
| `SUBSCRIPTION_FORMAT` | 否 | 旧根路径 `GET /` 的默认输出格式，默认 `ss` |
| `ALLOWED_METHODS` | 否 | 覆盖默认的 Shadowsocks cipher 白名单 |
| `TABLE_NAME` | 仅 AWS | DynamoDB 表名 |
| `RECORD_INDEX_NAME` | 仅 AWS | GSI 名称，默认 `RecordIndex` |
| `LISTEN_ADDR` | 仅 Go/Python | 监听地址，默认 `127.0.0.1:8080` |
| `STORAGE_PATH` | 仅 Go/Python | 本地 JSON 文档路径，默认 `./data/records.json` |
| `KV_NAMESPACE` | 仅 Workers | `wrangler.jsonc` 里的 KV 绑定名 |

## 本地校验

先跑完整自动化测试：

```bash
make test
```

也可以按语言分别执行：

```bash
npm install
npm test
go test ./...
python3 -m unittest discover -s pytests -p 'test_*.py' -v
```

## 调用示例

新增或更新一个 Shadowsocks 记录：

```bash
curl -X POST 'https://你的地址/webhook' \
  -H 'Authorization: Bearer WRITE_TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{
    "ruleName": "Home-SS",
    "host": "edge.example.com",
    "port": 443,
    "method": "aes-256-gcm",
    "password": "replace-with-password"
  }'
```

新增一个只在 Dashboard 展示的 `site` 记录：

```bash
curl -X POST 'https://你的地址/webhook' \
  -H 'Authorization: Bearer WRITE_TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{
    "ruleName": "Home-NAS",
    "type": "site",
    "host": "nas.example.com",
    "port": 443
  }'
```

获取订阅：

```bash
curl 'https://你的地址/subscription?subtype=ss&api_key=READ_TOKEN'
curl 'https://你的地址/subscription?subtype=clash&api_key=READ_TOKEN'
curl -H 'Authorization: Bearer READ_TOKEN' 'https://你的地址/'
```

不打开 Dashboard 页面，直接读记录接口：

```bash
curl -H 'Authorization: Bearer READ_TOKEN' \
  'https://你的地址/api/records'
```

按 `ruleName` 删除记录：

```bash
curl -X POST 'https://你的地址/api/delete' \
  -H 'Authorization: Bearer WRITE_TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{"ruleName":"Home-SS"}'
```

## Cloudflare Workers

v2 主要面向 Workers 部署。

1. 安装依赖：

```bash
npm install
```

2. 创建 KV namespace，并把 id 填到 [`wrangler.jsonc`](wrangler.jsonc)。

3. 设置必需 secrets：

```bash
npx wrangler secret put READ_TOKEN
npx wrangler secret put WRITE_TOKEN
npx wrangler secret put SESSION_SECRET
```

4. 调整 [`wrangler.jsonc`](wrangler.jsonc)：

- `main: "GoHomeEasy_CF.js"` 时由 `SUBSCRIPTION_FORMAT` 控制旧根路径默认格式
- `GoHomeEasy_CF_SS.js` 和 `GoHomeEasy_CF_Clash.js` 是固定格式兼容入口
- `SESSION_TTL_SECONDS` 可选

5. 部署：

```bash
npx wrangler deploy
```

已知限制：

- KV 在不同 PoP 之间是最终一致的，更新或删除后短时间内其他地区可能仍看到旧记录。

## AWS Lambda + DynamoDB

1. 安装依赖：

```bash
npm install
```

2. 创建 DynamoDB 表：

- 表名：`Subscription` 或你自己的名字
- 主键：`id`，类型 `String`

3. 给 v2 记录增加 GSI：

- 索引名：`RecordIndex` 或你自己的名字
- 分区键：`gsi1pk`，类型 `String`
- 排序键：`gsi1sk`，类型 `String`

4. 打包 Lambda：

```bash
zip -r gohomeeasy-aws.zip GoHomeEasy_AWS.js GoHomeEasy_AWS_SS.js GoHomeEasy_AWS_Clash.js src package.json package-lock.json node_modules
```

5. 配置环境变量：

- `READ_TOKEN`
- `WRITE_TOKEN`
- `SESSION_SECRET`
- `TABLE_NAME=Subscription`
- 如果索引名不是默认值，再加 `RECORD_INDEX_NAME=RecordIndex`
- 使用 `GoHomeEasy_AWS.js` 时，再加 `SUBSCRIPTION_FORMAT=ss` 或 `clash`

6. 配置 Handler：

- `GoHomeEasy_AWS.handler`
- `GoHomeEasy_AWS_SS.handler`
- `GoHomeEasy_AWS_Clash.handler`

7. 给 Lambda 执行角色授权：

- `dynamodb:GetItem`
- `dynamodb:PutItem`
- `dynamodb:DeleteItem`
- `dynamodb:Query`

8. 通过 API Gateway HTTP API 暴露函数。

已知限制：

- DynamoDB GSI 查询也是最终一致的，刚写入或刚删除的记录不一定能立刻读到。

## Go 自托管

1. 编译：

```bash
go build -o gohomeeasy ./cmd/gohomeeasy
```

2. 配置环境变量：

```bash
export READ_TOKEN=replace-with-read-token
export WRITE_TOKEN=replace-with-write-token
export SESSION_SECRET=replace-with-long-random-secret
export SUBSCRIPTION_FORMAT=ss
export LISTEN_ADDR=127.0.0.1:8080
export STORAGE_PATH=/var/lib/gohomeeasy/records.json
```

3. 启动：

```bash
./gohomeeasy
```

4. 如需 TLS 和域名，前面挂 Nginx 或 Caddy。

5. 仓库里带了一个 [`gohomeeasy.service`](gohomeeasy.service) 作为 `systemd` 示例。

6. 如果你用 Nginx，可以直接从 [`deploy/nginx-gohomeeasy.conf.example`](deploy/nginx-gohomeeasy.conf.example) 改起。`Host` 和 `X-Forwarded-Proto` 这些转发头是必须的，否则 Dashboard 的同源校验和安全 Cookie 会出问题。

## Python 自托管

这条路径不依赖 Node.js，也不需要额外 Python 包。

1. 配置环境变量：

```bash
export READ_TOKEN=replace-with-read-token
export WRITE_TOKEN=replace-with-write-token
export SESSION_SECRET=replace-with-long-random-secret
export SUBSCRIPTION_FORMAT=ss
export LISTEN_ADDR=127.0.0.1:8080
export STORAGE_PATH=/var/lib/gohomeeasy/records.json
```

2. 启动：

```bash
python3 gohomeeasy.py
```

3. 保证 [`dashboard.html`](dashboard.html) 和 [`gohomeeasy.py`](gohomeeasy.py) 在同一目录。

4. 仓库里带了一个 [`gohomeeasy-python.service`](gohomeeasy-python.service) 作为 Python 版 `systemd` 示例。

5. 如果你用 Nginx，也可以直接参考 [`deploy/nginx-gohomeeasy.conf.example`](deploy/nginx-gohomeeasy.conf.example)。

## Go/Python 反代说明

- 建议在 Nginx 或 Caddy 上终止 TLS，再反代到 `127.0.0.1:8080`。
- 必须转发 `Host`、`X-Forwarded-Host`、`X-Forwarded-Proto`。
- 少了这些头，Dashboard 的同源判断和 `Secure` Cookie 行为都会不对。

## 部署后 smoke test

每次部署或改配置后，建议直接跑仓库自带脚本：

```bash
./scripts/smoke-test.sh https://你的地址 READ_TOKEN WRITE_TOKEN
```

或者通过 Makefile：

```bash
make smoke ENDPOINT=https://你的地址 READ_TOKEN=... WRITE_TOKEN=...
```

这个 smoke test 会检查：

- `/healthz`
- webhook 写入
- SS 和 Clash 订阅输出
- `/api/records`
- Dashboard 登录跳转
- `/api/delete` 清理

## 订阅地址

- 兼容旧根路径：`GET /?api_key=READ_TOKEN`
- 显式 SS：`GET /subscription?subtype=ss&api_key=READ_TOKEN`
- 显式 Clash：`GET /subscription?subtype=clash&api_key=READ_TOKEN`
- 也支持 header：`Authorization: Bearer READ_TOKEN`

保留旧根路径的意义是：没有 `subtype` 的老客户端仍会继续遵守 `SUBSCRIPTION_FORMAT`。

## Dashboard

Dashboard 是一个无构建步骤的静态 HTML 页面。

- 展示 SS 和 Clash 两条订阅链接
- 同时列出 `ss` 与 `site` 记录
- 密码默认隐藏，可在浏览器中点开
- 只读模式下禁用删除按钮
- 当还没有 v2 `ss` 记录时，会显示 legacy fallback 提示

## 说明

- 订阅输出会按 `ruleName` 升序排列，保证稳定。
- `site` 永远不会进入订阅。
- 如果既没有 v2 `ss` 记录，也没有 legacy 内容，订阅接口返回 `204`。
- 旧版本地“纯字符串订阅文件”在首次读取时会被当成 legacy 内容处理，升级后不会立刻把现有订阅清空。
