# KidShield 后端

## 部署方式

### 方式一：Zeabur（推荐，国内直接访问）
1. 打开 https://zeabur.com 注册账号
2. 点击 "New Project" → "Deploy from GitHub"
3. 选择 `kuilinan/kidshield-backend` 仓库
4. Zeabur 会自动部署，部署完成后会给一个 `*.zeabur.app` 域名
5. 把这个域名记下来，后面改 App 里用

### 方式二：Cloudflare Workers（反向代理）
1. 打开 https://workers.cloudflare.com 
2. 创建一个新的 Worker
3. 把 `worker-proxy.js` 的内容复制进去
4. 部署后会得到一个 `*.workers.dev` 域名
5. 这个域名国内可以访问

## 修改 App 中的 API 地址
拿到新域名后，修改：
`app/src/main/java/com/yousafdev/KidShield/Network/ApiClient.java`
中的 `BASE_URL` 为新域名。
