/* StarMap 星图 V1.0 - API 封装（§6 REST 契约） */
(function (global) {
  'use strict';

  const BASE = ''; // 同源部署；file:// 下请求会失败并优雅降级

  // 列表接口的元信息（总数/本次上限），按路径记录。
  // 为什么不用全局变量：资产页会并发请求 /assets 与 /assets/stats，
  // 全局变量会被后到的响应覆盖，页面上就会显示错的"共 N 条"。
  const listMeta = {};

  async function req(method, path, body) {
    const init = { method, headers: {} };
    if (body instanceof FormData) {
      init.body = body; // multipart，浏览器自动带 boundary
    } else if (body !== undefined && body !== null) {
      init.headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(body);
    }
    let resp;
    try {
      resp = await fetch(BASE + path, init);
    } catch (e) {
      throw new Error('无法连接后端服务（' + e.message + '）');
    }
    if (!resp.ok) {
      let msg = 'HTTP ' + resp.status;
      try {
        const data = await resp.json();
        if (data && data.error) msg = data.error;
      } catch (_) { /* ignore */ }
      throw new Error(msg);
    }
    if (resp.status === 204) return null;
    // 列表接口带 X-Total-Count / X-Result-Limit：total 是**当前筛选条件下**的服务端总数。
    //
    // 必须用「头是否存在」判断，不能用 total > 0：
    // 搜不到任何结果时 total 就是 0，早期写成 if (total > 0) 会把这次响应直接丢弃，
    // 于是 meta 里留着上一次的旧总数——列表已经空了，徽标还显示「120 台」，
    // 用户会以为"筛掉了但还有 120 台"，比不显示更误导。
    const rawTotal = resp.headers.get('X-Total-Count');
    if (rawTotal !== null) {
      const cap = Number(resp.headers.get('X-Result-Limit') || 0);
      listMeta[path.split('?')[0]] = { total: Number(rawTotal) || 0, limit: cap };
    }
    const text = await resp.text();
    if (!text) return null;
    // 后端若返回 HTML（异常兜底）而非 JSON，给出友好错误而非 raw "Unexpected token '<'"
    const t = text.trim();
    if (t.charAt(0) === '<') {
      throw new Error('服务返回了非 JSON 响应（可能是接口不存在或服务异常），请检查请求路径与后端日志');
    }
    try {
      return JSON.parse(text);
    } catch (e) {
      throw new Error('响应不是有效 JSON：' + (e && e.message ? e.message : e));
    }
  }

  const API = {
    // 列表元信息：{total, limit}；未取到返回 {total:0, limit:0}。
    // 1.3.1 起列表走真·服务端分页，total 是**当前筛选条件下**的服务端总数，
    // 分页器据此计算总页数；旧的"total > list.length 即被截断"用法不再适用。
    meta: (p) => listMeta[p] || { total: 0, limit: 0 },
    // 拓扑
    topology: () => req('GET', '/api/topology'),
    subnets: () => req('GET', '/api/subnets'),
    node: (id) => req('GET', '/api/nodes/' + encodeURIComponent(id)),
    // 节点情报（V1.5）：本地优先，本地没有才回源。
    // refresh=true 跳过本地直接问情报平台（人主动点"刷新"时才用）。
    tiLookup: (id, refresh) =>
      req('GET', '/api/nodes/' + encodeURIComponent(id) + '/ti' + (refresh ? '?refresh=1' : '')),
    // 本地情报库：条数 / 判定分布 / 来源 / 最后入库时间
    intelStats: () => req('GET', '/api/intel/stats'),
    stats: () => req('GET', '/api/stats'),
    health: () => req('GET', '/api/health'),
    // 事件
    // 1.3.1 起支持真·分页：q 为服务端模糊搜索，limit/offset 为分页窗口。
    // 注意：筛选必须交给服务端。前端本地筛选 + 服务端分页 =
    // 用户看到的"筛选结果"只覆盖当前页，会得出"没有匹配项"的错误结论。
    events: (params = {}) => {
      const qs = new URLSearchParams();
      if (params.status) qs.set('status', params.status);
      if (params.type) qs.set('type', params.type);
      if (params.q) qs.set('q', params.q);
      if (params.limit) qs.set('limit', params.limit);
      if (params.offset) qs.set('offset', params.offset);
      const s = qs.toString();
      return req('GET', '/api/events' + (s ? '?' + s : ''));
    },
    reviewEvent: (id, action, note, reviewer) =>
      req('POST', '/api/events/' + encodeURIComponent(id) + '/review', { action, note, reviewer }),
    // 白名单
    whitelist: () => req('GET', '/api/whitelist'),
    createWhitelist: (entry) => req('POST', '/api/whitelist', entry),
    updateWhitelist: (id, entry) => req('PUT', '/api/whitelist/' + encodeURIComponent(id), entry),
    deleteWhitelist: (id) => req('DELETE', '/api/whitelist/' + encodeURIComponent(id)),
    // 网络域
    domains: () => req('GET', '/api/domains'),
    createDomain: (d) => req('POST', '/api/domains', d),
    updateDomain: (id, d) => req('PUT', '/api/domains/' + encodeURIComponent(id), d),
    deleteDomain: (id) => req('DELETE', '/api/domains/' + encodeURIComponent(id)),
    // 数据接入
    uploadPcap: (file) => {
      const fd = new FormData();
      fd.append('file', file);
      return req('POST', '/api/ingest/pcap', fd);
    },
    triggerProbe: (type, target) => req('POST', '/api/probe/trigger', { type, target }),
    // 实时抓包控制（§10.6）
    captureStart: () => req('POST', '/api/capture/start'),
    captureStop: () => req('POST', '/api/capture/stop'),
    captureStatus: () => req('GET', '/api/capture/status'),
    // 子网下钻（§10.6）
    subnetTopology: (cidr) => req('GET', '/api/topology/subnet/' + encodeURIComponent(cidr)),
    // 配置与审计
    getConfig: () => req('GET', '/api/config'),
    putConfig: (cfg) => req('PUT', '/api/config', cfg),
    audit: () => req('GET', '/api/audit'),
    // 主机资产库 + 端口记录（V1.2）
    // params 支持对象 {status, q, limit, offset}；也兼容旧的 API.assets('archived') 字符串写法。
    assets: (params) => {
      if (typeof params === 'string') params = { status: params };
      params = params || {};
      const qs = new URLSearchParams();
      if (params.status) qs.set('status', params.status);
      if (params.q) qs.set('q', params.q);
      if (params.limit) qs.set('limit', params.limit);
      if (params.offset) qs.set('offset', params.offset);
      const s = qs.toString();
      return req('GET', '/api/assets' + (s ? '?' + s : ''));
    },
    assetStats: () => req('GET', '/api/assets/stats'),
    archiveAsset: (payload) => req('POST', '/api/assets/archive', payload),
    updateAsset: (key, payload) => req('PUT', '/api/assets/' + encodeURIComponent(key), payload),
    deleteAsset: (key) => req('DELETE', '/api/assets/' + encodeURIComponent(key)),
    ports: (params = {}) => {
      const qs = new URLSearchParams();
      if (params.ip) qs.set('ip', params.ip);
      if (params.node_key) qs.set('node_key', params.node_key);
      if (params.q) qs.set('q', params.q);
      if (params.limit) qs.set('limit', params.limit);
      if (params.offset) qs.set('offset', params.offset);
      const s = qs.toString();
      return req('GET', '/api/ports' + (s ? '?' + s : ''));
    },
    scanPorts: (target) => req('POST', '/api/ports/scan', { target }),
    scanPortsStatus: (id) => req('GET', '/api/ports/scan/' + encodeURIComponent(id)),
    // 主动发现（V1.6）：内置端口扫描 + 服务指纹，不依赖 nmap
    discoverPlan: (profile) => req('GET', '/api/discover/plan' + (profile ? '?profile=' + encodeURIComponent(profile) : '')),
    discoverRun: (payload) => req('POST', '/api/discover/run', payload),
    discoverStatus: (id) => req('GET', '/api/discover/status/' + encodeURIComponent(id)),
    // 探针注册（V1.3）
    probes: () => req('GET', '/api/probes'),
    deleteProbe: (id) => req('DELETE', '/api/probes/' + encodeURIComponent(id)),
    // 资产台账对照（V1.7）
    ledger: () => req('GET', '/api/ledger'),
    ledgerDiff: () => req('GET', '/api/ledger/diff'),
    ledgerImport: (file) => {
      const fd = new FormData();
      fd.append('file', file);
      return req('POST', '/api/ledger/import', fd);
    },
    ledgerImportText: (csv, batch) => req('POST', '/api/ledger/import', { csv, batch }),
    ledgerClear: () => req('DELETE', '/api/ledger'),
    // 七层转发识别（V1.8）：代理节点 + 背后真实客户端
    proxies: () => req('GET', '/api/proxies'),
    // 主动发现任务账（V1.6）：历史任务列表 / 详情 / 取消
    tasks: (params = {}) => {
      const qs = new URLSearchParams();
      if (params.status) qs.set('status', params.status);
      if (params.limit) qs.set('limit', params.limit);
      if (params.offset) qs.set('offset', params.offset);
      const s = qs.toString();
      return req('GET', '/api/tasks' + (s ? '?' + s : ''));
    },
    task: (id) => req('GET', '/api/tasks/' + encodeURIComponent(id)),
    cancelTask: (id) => req('POST', '/api/tasks/' + encodeURIComponent(id) + '/cancel'),
    // 变更视图（V1.6）：窗口内新增 / 不再活动的端口
    changes: (days) => req('GET', '/api/changes' + (days ? '?days=' + Number(days) : '')),
    // 趋势（V1.6）：最近 N 天新增资产/端口/事件
    trend: (days) => req('GET', '/api/trend' + (days ? '?days=' + Number(days) : '')),
    // 导出（V1.6）：只负责拼 URL，真正的下载走下面的 download()
    exportURL: (kind, params = {}) => {
      const qs = new URLSearchParams();
      Object.keys(params).forEach((k) => {
        if (params[k]) qs.set(k, params[k]);
      });
      const s = qs.toString();
      return '/api/export/' + kind + '.csv' + (s ? '?' + s : '');
    },
    // 下载 CSV（V1.6）。
    //
    // 为什么不直接 location.href = exportURL()：
    // 服务端返回 401/403（会话过期、只读账号）时，浏览器会把**整页**跳到那段
    // JSON 错误上，用户从导出页被踢到一个白底黑字的 {"error":"..."} 回不来。
    // fetch 能先看状态码，失败时弹 toast、页面原地不动。
    //
    // 内存边界：导出在服务端被 exportMaxRows（20 万行）钉死，单次响应最多
    // 几十 MB，blob 放内存里没问题；不设上限才是真的会把标签页撑爆。
    download: async (kind, params = {}) => {
      const url = API.exportURL(kind, params);
      let resp;
      try {
        resp = await fetch(url, { credentials: 'same-origin' });
      } catch (e) {
        throw new Error('无法连接后端服务（' + e.message + '）');
      }
      if (!resp.ok) {
        let msg = 'HTTP ' + resp.status;
        try {
          const data = await resp.json();
          if (data && data.error) msg = data.error;
        } catch (_) { /* ignore */ }
        throw new Error(msg);
      }
      const blob = await resp.blob();
      // 文件名以服务端 Content-Disposition 为准（带时间戳，导出多次不会互相覆盖）
      let name = 'starmap-' + kind + '.csv';
      const cd = resp.headers.get('Content-Disposition') || '';
      const m = /filename="?([^";]+)"?/.exec(cd);
      if (m && m[1]) name = m[1];
      const href = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = href;
      a.download = name;
      a.style.display = 'none';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      // 立即 revoke 在部分浏览器里会让下载拿不到数据，延后释放
      setTimeout(() => URL.revokeObjectURL(href), 10000);
      return { name: name, bytes: blob.size };
    },
  };

  global.API = API;
})(window);
