// KidShield API 反向代理 - 部署到 Cloudflare Workers
// 解决 Vercel 域名在国内被 DNS 污染的问题
// 使用方法：在 Cloudflare Dashboard 新建 Worker，粘贴此代码

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const targetURL = 'https://kid-shield-five.vercel.app' + url.pathname + url.search;
    
    const modifiedRequest = new Request(targetURL, {
      method: request.method,
      headers: request.headers,
      body: request.method === 'GET' || request.method === 'HEAD' ? null : request.body,
    });
    
    try {
      const response = await fetch(modifiedRequest);
      return response;
    } catch (e) {
      return new Response(JSON.stringify({ error: 'Proxy error: ' + e.message }), {
        status: 502,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  }
}
