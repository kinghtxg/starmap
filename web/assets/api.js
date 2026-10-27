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
    // 列表接口会带 X-Total-Count / X-Result-Limit：服务端有容量护栏，
    // 超过上限的部分不返回。前端必须知道"被截断了"，否则用户会以为数据丢了。
    const total = Number(resp.headers.get('X-Total-Count') || 0);
    const cap = Number(resp.headers.get('X-Result-Limit') || 0);
    if (total > 0) {
      listMeta[path.split('?')[0]] = { total: total, limit: cap };
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
    // 用法：const m = API.meta('/api/ports'); if (m.total > list.length) 显示截断提示
    meta: (p) => listMeta[p] || { total: 0, limit: 0 },
    // 拓扑
    topology: () => req('GET', '/api/topology'),
    subnets: () => req('GET', '/api/subnets'),
    node: (id) => req('GET', '/api/nodes/' + encodeURIComponent(id)),
    stats: () => req('GET', '/api/stats'),
    health: () => req('GET', '/api/health'),
    // 事件
    events: (params = {}) => {
      const qs = new URLSearchParams();
      if (params.status) qs.set('status', params.status);
      if (params.type) qs.set('type', params.type);
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
    assets: (status) => req('GET', '/api/assets' + (status ? '?status=' + encodeURIComponent(status) : '')),
    assetStats: () => req('GET', '/api/assets/stats'),
    archiveAsset: (payload) => req('POST', '/api/assets/archive', payload),
    updateAsset: (key, payload) => req('PUT', '/api/assets/' + encodeURIComponent(key), payload),
    deleteAsset: (key) => req('DELETE', '/api/assets/' + encodeURIComponent(key)),
    ports: (params = {}) => {
      const qs = new URLSearchParams();
      if (params.ip) qs.set('ip', params.ip);
      if (params.node_key) qs.set('node_key', params.node_key);
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
  };

  global.API = API;
})(window);
