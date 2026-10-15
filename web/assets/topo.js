/* ==========================================================================
   StarMap 星图 V1.1 —— 标准拓扑图渲染引擎（topo.js）
   纯原生 SVG 自绘，零第三方依赖（不使用 Cytoscape.js / D3 / jsPDF）
   观感基准：华为 eSight / 锐捷 RIIL / Zabbix 网管拓扑
   能力：标准设备图标 · 分层布局 · 正交折线 · 流光 · 平移缩放 · 框选 ·
        下钻 · 右键菜单 · 图例 · 缩略图 · 导出 PNG/SVG · 空态引导 · 大图保护
   ========================================================================== */
(function (global) {
  'use strict';

  var SM = global.SM = global.SM || {};

  /* ---------- 常量 ---------- */
  var NW = 52, NH = 52;            // 节点尺寸
  var COL_GAP = 138;               // 同层节点水平间距
  var ROW_INNER = 118;             // 层内子行垂直间距
  var BAND_GAP = 66;               // 层间留白（走线区）
  var PAD = 60;                    // 内容边距
  var LABEL_HIDE = 240;            // 超过该节点数隐藏全部标签
  var SUBLABEL_HIDE = 110;         // 超过该节点数隐藏副标签
  var FLOW_MAX_EDGES = 420;        // 超过该边数不做流光动画

  /* ---------- 风险色（与 theme.css 令牌一致，导出时需内联） ---------- */
  var RISK = {
    high: '#e34d59',
    mid: '#ff8800',
    low: '#0052d9',
    none: '#2ba471'
  };
  var BORDER = '#c9cfd8';

  /* ---------- 标准网络设备图标（24x24，线条风格） ---------- */
  var GLYPH = {
    router:
      '<rect x="2.6" y="14.6" width="18.8" height="5.6" rx="1.2"/>' +
      '<path d="M4.6 9.6h13.2"/><path d="M15.2 7.5 17.8 9.6 15.2 11.7"/>' +
      '<path d="M19.4 13.2H6.2"/><path d="M8.8 11.1 6.2 13.2 8.8 15.3"/>' +
      '<circle class="sm-fill" cx="6.4" cy="17.4" r=".85"/><circle class="sm-fill" cx="9.2" cy="17.4" r=".85"/>',
    switch_:
      '<rect x="2.6" y="4.6" width="18.8" height="14.8" rx="1.4"/>' +
      '<path d="M5.2 9.2h11.4"/><path d="M13.8 7.1 16.4 9.2 13.8 11.3"/>' +
      '<path d="M5.2 15h11.4"/><path d="M13.8 12.9 16.4 15 13.8 17.1"/>',
    firewall:
      '<path d="M2.6 5.6h18.8v13H2.6z"/>' +
      '<path d="M2.6 10h18.8M2.6 14.4h18.8"/>' +
      '<path d="M8.2 5.6V10M13.8 5.6V10M5.4 10v4.4M10.9 10v4.4M16.5 10v4.4M8.2 14.4v4.2M13.8 14.4v4.2"/>',
    server:
      '<rect x="4.2" y="3.4" width="15.6" height="5" rx="1"/>' +
      '<rect x="4.2" y="9.5" width="15.6" height="5" rx="1"/>' +
      '<rect x="4.2" y="15.6" width="15.6" height="5" rx="1"/>' +
      '<circle class="sm-fill" cx="7.4" cy="5.9" r=".8"/><circle class="sm-fill" cx="7.4" cy="12" r=".8"/><circle class="sm-fill" cx="7.4" cy="18.1" r=".8"/>' +
      '<path d="M10.6 5.9h6M10.6 12h6M10.6 18.1h6"/>',
    pc:
      '<rect x="2.8" y="4.2" width="18.4" height="12" rx="1.3"/>' +
      '<path d="M9.2 19.6h5.6M12 16.2v3.4"/>',
    cloud:
      '<path d="M7.2 18.6h9.9a3.6 3.6 0 0 0 .5-7.17 5.4 5.4 0 0 0-10.2-1.24A4.3 4.3 0 0 0 7.2 18.6z"/>',
    subnet:
      '<rect x="2.4" y="6.4" width="19.2" height="11.2" rx="1.6"/>' +
      '<rect x="5" y="9.2" width="3.6" height="5.6" rx=".8"/>' +
      '<rect x="10.2" y="9.2" width="3.6" height="5.6" rx=".8"/>' +
      '<rect x="15.4" y="9.2" width="3.6" height="5.6" rx=".8"/>',
    unknown:
      '<rect x="2.8" y="2.8" width="18.4" height="18.4" rx="2"/>' +
      '<path d="M9.4 9.3a2.6 2.6 0 1 1 2.4 3.5c-.8.3-1.1 1-1.1 1.7v.3"/>' +
      '<circle class="sm-fill" cx="10.7" cy="16.8" r=".9"/>'
  };
  var TYPE_LABEL = {
    router: '路由器', switch_: '交换机', firewall: '防火墙', server: '服务器',
    pc: '终端', cloud: '外部网络', subnet: '网段聚合', unknown: '未知设备'
  };
  var LAYER_LABEL = ['外部网络', '核心层', '汇聚层', '接入层', '终端层'];

  /* 工具栏图标（内联，避免依赖外部模块） */
  function ti(d) {
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" ' +
      'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="' + d + '"/></svg>';
  }
  var TICO = {
    plus: ti('M12 6v12M6 12h12'),
    minus: ti('M6 12h12'),
    fit: ti('M4 9V5a1 1 0 0 1 1-1h4M20 9V5a1 1 0 0 0-1-1h-4M4 15v4a1 1 0 0 0 1 1h4M20 15v4a1 1 0 0 1-1 1h-4'),
    layout: ti('M4 4h6v6H4V4zm10 0h6v6h-6V4zM4 14h6v6H4v-6zm10 0h6v6h-6v-6z')
  };

  /* ---------- 工具函数 ---------- */
  function esc(s) {
    return String(s === null || s === undefined ? '' : s)
      .replace(/[&<>"']/g, function (c) {
        return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
      });
  }
  function clamp(v, a, b) { return v < a ? a : v > b ? b : v; }
  function num(v) { return Number(v) || 0; }

  function primaryIP(n) {
    if (n.IPs && n.IPs.length) return String(n.IPs[0]).replace(/\/.*$/, '');
    var m = String(n.ID || '').match(/^(\d+\.\d+\.\d+\.\d+)/);
    return m ? m[1] : '';
  }
  function isPrivateIP(ip) {
    var m = String(ip || '').match(/^(\d+)\.(\d+)\./);
    if (!m) return false;
    var a = +m[1], b = +m[2];
    return a === 10 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31) ||
      (a === 169 && b === 254) || a === 127 || a === 0;
  }
  function isAggNode(n) {
    if (n.Aggregated) return true;
    var id = String(n.ID || '');
    return id.indexOf('subnet:') === 0;
  }
  function isExtNode(n) {
    var id = String(n.ID || '');
    if (id.indexOf('ext:') === 0) return true;
    if (n.Labels && n.Labels.indexOf('external-agg') >= 0) return true;
    var ip = primaryIP(n);
    return !!ip && !isPrivateIP(ip) && !isAggNode(n);
  }

  /* 正交折线：带圆角 */
  function norm(from, to) {
    var dx = from[0] - to[0], dy = from[1] - to[1];
    var d = Math.sqrt(dx * dx + dy * dy) || 1;
    return [dx / d, dy / d];
  }
  function dist(a, b) { var dx = a[0] - b[0], dy = a[1] - b[1]; return Math.sqrt(dx * dx + dy * dy); }
  function elbow(pts, r) {
    if (pts.length < 2) return '';
    var d = 'M ' + pts[0][0].toFixed(1) + ' ' + pts[0][1].toFixed(1);
    for (var i = 1; i < pts.length - 1; i++) {
      var p0 = pts[i - 1], p1 = pts[i], p2 = pts[i + 1];
      var rr = Math.min(r, dist(p0, p1) / 2, dist(p2, p1) / 2);
      if (rr < 0.5) { d += ' L ' + p1[0].toFixed(1) + ' ' + p1[1].toFixed(1); continue; }
      var v1 = norm(p0, p1), v2 = norm(p2, p1);
      var a0 = [p1[0] + v1[0] * rr, p1[1] + v1[1] * rr];
      var b0 = [p1[0] + v2[0] * rr, p1[1] + v2[1] * rr];
      d += ' L ' + a0[0].toFixed(1) + ' ' + a0[1].toFixed(1) +
        ' Q ' + p1[0].toFixed(1) + ' ' + p1[1].toFixed(1) + ' ' + b0[0].toFixed(1) + ' ' + b0[1].toFixed(1);
    }
    var last = pts[pts.length - 1];
    return d + ' L ' + last[0].toFixed(1) + ' ' + last[1].toFixed(1);
  }

  /* ---------- 分层布局 ---------- */
  function classify(n, deg) {
    if (isExtNode(n)) return { type: 'cloud', tier: 0 };
    if (isAggNode(n)) return { type: 'subnet', tier: 3 };
    if (deg >= 8) return { type: 'router', tier: 1 };
    if (deg >= 4) return { type: 'switch_', tier: 2 };
    if (deg >= 2) return { type: 'server', tier: 3 };
    return { type: 'pc', tier: 4 };
  }

  function layout(nodes, edges) {
    var ids = nodes.map(function (n) { return String(n.ID); });
    var idSet = {};
    ids.forEach(function (i) { idSet[i] = true; });
    var adj = {};
    ids.forEach(function (i) { adj[i] = []; });
    var deg = {};
    ids.forEach(function (i) { deg[i] = 0; });
    edges.forEach(function (e) {
      var a = String(e.SrcID), b = String(e.DstID);
      if (!idSet[a] || !idSet[b] || a === b) return;
      if (adj[a].indexOf(b) < 0) { adj[a].push(b); adj[b].push(a); deg[a]++; deg[b]++; }
    });

    // 1) 类型 / 初始层级
    var info = {};
    ids.forEach(function (i) {
      var n = nodes[ids.indexOf(i)];
      info[i] = classify(n, deg[i]);
    });

    // 2) BFS：以核心设备为源，算网络层级
    var src = ids.filter(function (i) {
      return info[i].type === 'router' || info[i].type === 'switch_';
    });
    if (!src.length) {
      var best = null, bd = -1;
      ids.forEach(function (i) {
        if (info[i].type === 'cloud' || info[i].type === 'subnet') return;
        if (deg[i] > bd) { bd = deg[i]; best = i; }
      });
      if (best) src = [best]; else src = ids.filter(function (i) { return info[i].type !== 'cloud'; }).slice(0, 1);
    }
    var distMap = {};
    var q = [], qi = 0;
    src.forEach(function (s) { distMap[s] = 0; q.push(s); });
    while (qi < q.length) {
      var u = q[qi++];
      adj[u].forEach(function (v) {
        if (!(v in distMap)) { distMap[v] = distMap[u] + 1; q.push(v); }
      });
    }
    ids.forEach(function (i) {
      var t = info[i];
      if (t.type === 'cloud') { t.layer = 0; return; }
      var d = (i in distMap) ? Math.min(distMap[i], 3) : 3;
      t.layer = clamp(Math.max(d, t.tier), 0, 4);
    });

    // 3) 压缩空层
    var used = {};
    ids.forEach(function (i) { used[info[i].layer] = true; });
    var sorted = Object.keys(used).map(Number).sort(function (a, b) { return a - b; });
    var remap = {};
    sorted.forEach(function (v, k) { remap[v] = k; });
    ids.forEach(function (i) { info[i].layer = remap[info[i].layer]; });
    var L = sorted.length || 1;

    // 4) 分层 + 重心排序
    var layers = [];
    for (var l = 0; l < L; l++) layers.push([]);
    ids.forEach(function (i) { layers[info[i].layer].push(i); });
    layers.forEach(function (arr) { arr.sort(); });

    var pos = {};
    layers.forEach(function (arr, li) { arr.forEach(function (id, i) { pos[id] = { l: li, i: i }; }); });
    function bary(id, refL) {
      var ns = adj[id].filter(function (v) { return pos[v] && pos[v].l === refL; });
      if (!ns.length) return pos[id].i;
      var s = 0;
      ns.forEach(function (v) { s += pos[v].i; });
      return s / ns.length;
    }
    for (var it = 0; it < 6; it++) {
      for (var f = 1; f < L; f++) {
        layers[f].sort(function (a, b) { return bary(a, f - 1) - bary(b, f - 1); });
        layers[f].forEach(function (id, i) { pos[id].i = i; });
      }
      for (var b2 = L - 2; b2 >= 0; b2--) {
        layers[b2].sort(function (a, b) { return bary(a, b2 + 1) - bary(b, b2 + 1); });
        layers[b2].forEach(function (id, i) { pos[id].i = i; });
      }
    }

    // 5) 坐标：层内网格对齐 + 超宽自动折行
    var xy = {}, band = [];
    var cursor = PAD;
    layers.forEach(function (arr, li) {
      var n = arr.length;
      var per = clamp(Math.ceil(Math.sqrt(n) * 2.2), 6, 16);
      var rows = Math.ceil(n / per);
      var top = cursor;
      for (var r = 0; r < rows; r++) {
        var row = arr.slice(r * per, (r + 1) * per);
        for (var i = 0; i < row.length; i++) {
          xy[row[i]] = {
            x: (i - (row.length - 1) / 2) * COL_GAP,
            y: top + NH / 2 + r * ROW_INNER
          };
        }
      }
      var bottom = top + rows * ROW_INNER;
      band.push({ top: top - 22, bottom: bottom - 22, layer: li });
      cursor = bottom + BAND_GAP;
    });

    return { xy: xy, band: band, layers: layers, info: info, adj: adj, deg: deg, layerCount: L };
  }

  /* ---------- 导出用内联样式（脱离 theme.css 也可独立渲染） ---------- */
  var EXPORT_CSS =
    '.sm-topo-band{fill:rgba(0,82,217,.03)}' +
    '.sm-topo-band-line{stroke:#edeff2;stroke-width:1;stroke-dasharray:4 4}' +
    '.sm-topo-band-label{font-size:11px;fill:#b3bac5;font-weight:600;letter-spacing:.08em;' +
    'font-family:"PingFang SC","Microsoft YaHei",Arial,sans-serif}' +
    '.sm-topo-edge{fill:none;stroke:#a9b4c6;stroke-linecap:round;stroke-linejoin:round}' +
    '.sm-topo-edge.is-inactive{stroke:#d4dae2;stroke-dasharray:5 4}' +
    '.sm-topo-plate{fill:#fff;stroke-width:1}' +
    '.sm-topo-glyph{fill:none;stroke:#4b5768;stroke-width:1.4;stroke-linecap:round;stroke-linejoin:round}' +
    '.sm-topo-glyph .sm-fill{fill:#4b5768;stroke:none}' +
    '.sm-topo-ring{fill:none;stroke:#8f9aab;stroke-width:1;stroke-dasharray:3 3}' +
    '.sm-topo-node.is-agg .sm-topo-plate{fill:#f4f7fd}' +
    '.sm-topo-label{font-size:11px;fill:#4b5768;text-anchor:middle;font-family:Consolas,Menlo,monospace}' +
    '.sm-topo-sublabel{font-size:10px;fill:#b3bac5;text-anchor:middle;' +
    'font-family:"PingFang SC","Microsoft YaHei",Arial,sans-serif}' +
    '.sm-topo-badge-bg{fill:#e34d59;stroke:#fff;stroke-width:1.5}' +
    '.sm-topo-badge-tx{font-size:9px;fill:#fff;text-anchor:middle;font-weight:700;' +
    'font-family:"PingFang SC","Microsoft YaHei",Arial,sans-serif}' +
    '.sm-topo-status{stroke-width:2;fill:none}' +
    '.sm-topo-title{font-size:15px;fill:#1d2129;font-weight:700;' +
    'font-family:"PingFang SC","Microsoft YaHei",Arial,sans-serif}' +
    '.sm-topo-meta{font-size:10px;fill:#86909c;font-family:"PingFang SC","Microsoft YaHei",Arial,sans-serif}';

  /* =======================================================================
     引擎
     ======================================================================= */
  function create(host, opts) {
    opts = opts || {};
    var NS = 'http://www.w3.org/2000/svg';

    var wrap = host;
    wrap.classList.add('sm-topo-wrap');
    wrap.innerHTML =
      '<svg class="sm-topo-canvas" xmlns="' + NS + '"><g class="sm-topo-viewport">' +
      '<g class="sm-topo-bands"></g><g class="sm-topo-edges"></g><g class="sm-topo-nodes"></g>' +
      '</g><g class="sm-topo-overlay2"></g></svg>' +
      '<div class="sm-topo-tools">' +
      '<button class="sm-btn is-icon is-sm" data-t="zin" title="放大">' + TICO.plus + '</button>' +
      '<button class="sm-btn is-icon is-sm" data-t="zout" title="缩小">' + TICO.minus + '</button>' +
      '<button class="sm-btn is-icon is-sm" data-t="fit" title="适应画布">' + TICO.fit + '</button>' +
      '<button class="sm-btn is-icon is-sm" data-t="relayout" title="重新布局">' + TICO.layout + '</button>' +
      '<div class="sm-topo-zoom" data-t="ztxt">100%</div>' +
      '</div>' +
      '<div class="sm-topo-legend"></div>' +
      '<div class="sm-topo-mm"></div>' +
      '<div class="sm-topo-notice sm-hide"></div>' +
      '<div class="sm-topo-overlay sm-hide"></div>';

    var svg = wrap.querySelector('.sm-topo-canvas');
    var viewport = wrap.querySelector('.sm-topo-viewport');
    var gBands = wrap.querySelector('.sm-topo-bands');
    var gEdges = wrap.querySelector('.sm-topo-edges');
    var gNodes = wrap.querySelector('.sm-topo-nodes');
    var elLegend = wrap.querySelector('.sm-topo-legend');
    var elMini = wrap.querySelector('.sm-topo-mm');
    var elNotice = wrap.querySelector('.sm-topo-notice');
    var elOverlay = wrap.querySelector('.sm-topo-overlay');
    var elZoom = wrap.querySelector('[data-t="ztxt"]');

    var data = { Nodes: [], Edges: [] };
    var geo = null;
    var alerts = {};
    var riskFilter = '';
    var tx = 0, ty = 0, k = 1;
    var selected = {};
    var hoverId = null;
    var handlers = {};
    var edgeIndex = {};   // edgeKey -> {grp, edge, flow, hit, a, b}
    var nodeIndex = {};   // id -> node obj
    var drag = null;

    /* ---------- 事件 ---------- */
    function on(evt, fn) { (handlers[evt] = handlers[evt] || []).push(fn); }
    function emit(evt, payload) { (handlers[evt] || []).forEach(function (fn) { fn(payload); }); }

    /* ---------- 渲染 ---------- */
    function render() {
      var nodes = data.Nodes || [], edges = data.Edges || [];
      gBands.innerHTML = ''; gEdges.innerHTML = ''; gNodes.innerHTML = '';
      edgeIndex = {}; nodeIndex = {};
      if (!nodes.length) {
        elMini.innerHTML = '';
        elNotice.classList.add('sm-hide');
        showEmpty();
        return;
      }
      hideOverlay();

      geo = layout(nodes, edges);
      nodes.forEach(function (n) { nodeIndex[String(n.ID)] = n; });

      var maxBytes = 1;
      edges.forEach(function (e) { maxBytes = Math.max(maxBytes, num(e.Bytes)); });

      var hideSub = nodes.length > SUBLABEL_HIDE;
      var hideLabel = nodes.length > LABEL_HIDE;

      /* 层背景带 */
      var minX = Infinity, maxX = -Infinity;
      Object.keys(geo.xy).forEach(function (id) {
        minX = Math.min(minX, geo.xy[id].x); maxX = Math.max(maxX, geo.xy[id].x);
      });
      if (!isFinite(minX)) { minX = 0; maxX = 0; }
      var bh = '';
      geo.band.forEach(function (b) {
        var name = LAYER_LABEL[b.layer] || ('第 ' + (b.layer + 1) + ' 层');
        bh += '<rect class="sm-topo-band" x="' + (minX - COL_GAP / 2) + '" y="' + b.top + '" width="' +
          (maxX - minX + COL_GAP) + '" height="' + (b.bottom - b.top) + '" rx="6"/>' +
          '<line class="sm-topo-band-line" x1="' + (minX - COL_GAP / 2) + '" y1="' + b.top + '" x2="' +
          (maxX + COL_GAP / 2) + '" y2="' + b.top + '"/>' +
          '<text class="sm-topo-band-label" x="' + (minX - COL_GAP / 2 + 8) + '" y="' + (b.top + 16) + '">' + esc(name) + '</text>';
      });
      gBands.innerHTML = bh;

      /* 边 */
      var eh = '';
      edges.forEach(function (e, i) {
        var a = String(e.SrcID), b = String(e.DstID);
        if (!geo.xy[a] || !geo.xy[b]) return;
        var w = 1 + 2.4 * Math.sqrt(num(e.Bytes) / maxBytes);
        var d = edgeD(a, b);
        if (!d) return;
        var inactive = e.Active === false;
        var key = 'e' + i;
        eh += '<g class="sm-topo-edge-grp" data-edge="' + key + '">' +
          '<path class="sm-topo-edge' + (inactive ? ' is-inactive' : '') + '" d="' + d + '" style="stroke-width:' + w.toFixed(2) + '"/>' +
          (!inactive && edges.length <= FLOW_MAX_EDGES && num(e.Bytes) > 0
            ? '<path class="sm-topo-flow" d="' + d + '" style="stroke-width:' + Math.max(1.2, w * 0.8).toFixed(2) + '"/>' : '') +
          '<path class="sm-topo-edge-hit" d="' + d + '"/>' +
          '</g>';
      });
      gEdges.innerHTML = eh;
      Array.prototype.forEach.call(gEdges.querySelectorAll('[data-edge]'), function (g) {
        var key = g.getAttribute('data-edge');
        edgeIndex[key] = {
          grp: g,
          edge: g.querySelector('.sm-topo-edge'),
          flow: g.querySelector('.sm-topo-flow'),
          hit: g.querySelector('.sm-topo-edge-hit')
        };
      });
      // 绑定端点以便拖拽时重算
      edges.forEach(function (e, i) {
        var rec = edgeIndex['e' + i];
        if (rec) { rec.a = String(e.SrcID); rec.b = String(e.DstID); rec.data = e; }
      });

      /* 节点 */
      var nh = '';
      nodes.forEach(function (n) {
        var id = String(n.ID);
        var p = geo.xy[id];
        if (!p) return;
        var t = geo.info[id] || { type: 'unknown' };
        var agg = t.type === 'subnet' || isAggNode(n);
        var lvl = n.RiskLevel || 'none';
        var color = RISK[lvl] || RISK.none;
        var active = n.Active !== false;
        var ip = primaryIP(n);
        var label = ip || (n.MAC ? String(n.MAC).slice(0, 17) : id);
        if (label.length > 18) label = label.slice(0, 17) + '…';
        var sub = agg ? (ip || '网段') : TYPE_LABEL[t.type];

        nh += '<g class="sm-topo-node' + (agg ? ' is-agg' : '') + (active ? '' : ' is-off') + '" data-id="' + esc(id) + '" transform="translate(' + p.x.toFixed(1) + ',' + p.y.toFixed(1) + ')">' +
          (agg ? '<rect class="sm-topo-ring" x="-32" y="-32" width="64" height="64" rx="10"/>' : '') +
          '<rect class="sm-topo-sel-ring" x="-31" y="-31" width="62" height="62" rx="8"/>' +
          '<rect class="sm-topo-plate" x="-26" y="-26" width="52" height="52" rx="6" ' +
          'style="stroke:' + color + ';stroke-width:' + (lvl === 'high' || lvl === 'mid' ? 1.8 : 1.2) + '"/>' +
          '<g class="sm-topo-glyph" transform="translate(-13.2,-13.2) scale(1.1)">' + (GLYPH[t.type] || GLYPH.unknown) + '</g>' +
          '<circle class="sm-topo-status" cx="17" cy="17" r="3.6" style="stroke:' + (active ? '#00a870' : '#b6bfcc') + ';fill:' + (active ? '#00a870' : '#d4dae2') + '"/>' +
          (alerts[id] ? '<g class="sm-topo-badge" transform="translate(20,-20)">' +
            '<circle class="sm-topo-badge-bg' + (lvl === 'high' ? '' : ' sm-topo-badge-warn') + '" r="8.5"/>' +
            '<text class="sm-topo-badge-tx" y="3">' + (alerts[id] > 99 ? '99+' : alerts[id]) + '</text></g>' : '') +
          (hideLabel ? '' : '<text class="sm-topo-label" y="40">' + esc(label) + '</text>' +
            (hideSub ? '' : '<text class="sm-topo-sublabel" y="53">' + esc(sub) + '</text>')) +
          '</g>';
      });
      gNodes.innerHTML = nh;

      /* 大图保护提示 */
      if (nodes.length > LABEL_HIDE) {
        elNotice.innerHTML = '<span>节点 ' + nodes.length + ' 个，已隐藏标签以保证渲染性能（缩放后可查看局部）</span>';
        elNotice.classList.remove('sm-hide');
      } else {
        elNotice.classList.add('sm-hide');
      }

      renderLegend();
      applyFilter();
      drawMini();
    }

    function edgeD(a, b) {
      var pa = geo.xy[a], pb = geo.xy[b];
      if (!pa || !pb) return '';
      var dy = pb.y - pa.y;
      if (Math.abs(dy) < 1) {           // 同层：绕行下方
        if (Math.abs(pb.x - pa.x) < 1) return '';
        var yb = pa.y + NH / 2 + 34;
        return elbow([[pa.x, pa.y + NH / 2], [pa.x, yb], [pb.x, yb], [pb.x, pb.y + NH / 2]], 10);
      }
      if (dy > 0) {                     // a 在上
        return elbow([[pa.x, pa.y + NH / 2], [pa.x, (pa.y + pb.y) / 2], [pb.x, (pa.y + pb.y) / 2], [pb.x, pb.y - NH / 2]], 12);
      }
      return elbow([[pa.x, pa.y - NH / 2], [pa.x, (pa.y + pb.y) / 2], [pb.x, (pa.y + pb.y) / 2], [pb.x, pb.y + NH / 2]], 12);
    }

    function renderLegend() {
      var types = {};
      (data.Nodes || []).forEach(function (n) {
        var t = (geo && geo.info[String(n.ID)]) || { type: 'unknown' };
        types[t.type] = 1;
      });
      var h = '<div class="sm-lg-t">设备类型</div>';
      Object.keys(GLYPH).forEach(function (t) {
        if (!types[t]) return;
        h += '<div class="sm-lg-i"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.4" ' +
          'stroke-linecap="round" stroke-linejoin="round">' + GLYPH[t] + '</svg><span>' + esc(TYPE_LABEL[t]) + '</span></div>';
      });
      h += '<div class="sm-lg-t">风险等级</div>';
      ['high', 'mid', 'low', 'none'].forEach(function (lv) {
        h += '<div class="sm-lg-i"><span class="sm-lg-sw" style="background:' + RISK[lv] + '"></span><span>' +
          esc({ high: '高风险', mid: '中风险', low: '低风险', none: '正常' }[lv]) + '</span></div>';
      });
      h += '<div class="sm-lg-t">链路</div>' +
        '<div class="sm-lg-i"><span class="sm-lg-sw" style="background:#a9b4c6;height:3px"></span><span>粗细 = 流量</span></div>' +
        '<div class="sm-lg-i"><span class="sm-lg-sw" style="background:repeating-linear-gradient(90deg,#0052d9 0 4px,transparent 4px 8px)"></span><span>虚线 = 已老化</span></div>' +
        '<div class="sm-lg-i"><span class="sm-lg-sw" style="background:#fff;border:1px dashed #8f9aab"></span><span>双环 = 可下钻</span></div>';
      elLegend.innerHTML = h;
    }

    /* ---------- 视口变换 ---------- */
    function applyTransform() {
      viewport.setAttribute('transform', 'translate(' + tx.toFixed(2) + ',' + ty.toFixed(2) + ') scale(' + k.toFixed(4) + ')');
      elZoom.textContent = Math.round(k * 100) + '%';
      updateMiniView();
    }
    function bbox() {
      if (!geo) return { x: 0, y: 0, w: 1, h: 1 };
      var x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
      Object.keys(geo.xy).forEach(function (id) {
        var p = geo.xy[id];
        x0 = Math.min(x0, p.x - 40); x1 = Math.max(x1, p.x + 40);
        y0 = Math.min(y0, p.y - 34); y1 = Math.max(y1, p.y + 62);
      });
      if (!isFinite(x0)) return { x: 0, y: 0, w: 1, h: 1 };
      return { x: x0, y: y0, w: x1 - x0, h: y1 - y0 };
    }
    function size() {
      var r = wrap.getBoundingClientRect();
      return { w: Math.max(120, r.width), h: Math.max(120, r.height) };
    }
    function fit() {
      var b = bbox(), s = size();
      k = clamp(Math.min(s.w / b.w, s.h / b.h) * 0.92, 0.08, 2.2);
      tx = (s.w - b.w * k) / 2 - b.x * k;
      ty = (s.h - b.h * k) / 2 - b.y * k;
      applyTransform();
    }
    function zoomAt(cx, cy, factor) {
      var nk = clamp(k * factor, 0.08, 4);
      if (nk === k) return;
      tx = cx - (cx - tx) * (nk / k);
      ty = cy - (cy - ty) * (nk / k);
      k = nk;
      applyTransform();
    }
    function zoomBy(f) { var s = size(); zoomAt(s.w / 2, s.h / 2, f); }
    function toGraph(cx, cy) {
      var r = svg.getBoundingClientRect();
      return { x: (cx - r.left - tx) / k, y: (cy - r.top - ty) / k };
    }
    function centerOn(id) {
      var p = geo && geo.xy[id];
      if (!p) return;
      var s = size();
      tx = s.w / 2 - p.x * k;
      ty = s.h / 2 - p.y * k;
      applyTransform();
    }

    /* ---------- 缩略图 ---------- */
    function drawMini() {
      var b = bbox();
      var mw = 176, mh = 116;
      var pad = 6;
      var sk = Math.min((mw - pad * 2) / b.w, (mh - pad * 2) / b.h);
      var ox = pad + (mw - pad * 2 - b.w * sk) / 2 - b.x * sk;
      var oy = pad + (mh - pad * 2 - b.h * sk) / 2 - b.y * sk;
      var h = '<svg viewBox="0 0 ' + mw + ' ' + mh + '">';
      var r = Math.max(1.2, Math.min(4, 40 * sk));
      Object.keys(geo.xy).forEach(function (id) {
        var p = geo.xy[id];
        var n = nodeIndex[id] || {};
        var lvl = n.RiskLevel || 'none';
        h += '<rect class="sm-mm-node" x="' + (p.x * sk + ox - r / 2).toFixed(1) + '" y="' + (p.y * sk + oy - r / 2).toFixed(1) +
          '" width="' + r.toFixed(1) + '" height="' + r.toFixed(1) + '" rx="0.6" style="fill:' +
          (lvl === 'none' ? '#b6bfcc' : RISK[lvl]) + '"/>';
      });
      h += '<rect class="sm-mm-view" data-mv="1" x="0" y="0" width="10" height="10"/></svg>';
      elMini.innerHTML = h;
      elMini.__m = { sk: sk, ox: ox, oy: oy, b: b };
      updateMiniView();
    }
    function updateMiniView() {
      var m = elMini.__m;
      if (!m) return;
      var v = elMini.querySelector('[data-mv]');
      if (!v) return;
      var s = size();
      var gx = -tx / k, gy = -ty / k, gw = s.w / k, gh = s.h / k;
      v.setAttribute('x', (gx * m.sk + m.ox).toFixed(1));
      v.setAttribute('y', (gy * m.sk + m.oy).toFixed(1));
      v.setAttribute('width', Math.max(4, gw * m.sk).toFixed(1));
      v.setAttribute('height', Math.max(4, gh * m.sk).toFixed(1));
    }

    /* ---------- 风险筛选 / 高亮 ---------- */
    function applyFilter() {
      Array.prototype.forEach.call(gNodes.querySelectorAll('.sm-topo-node'), function (el) {
        var id = el.getAttribute('data-id');
        var n = nodeIndex[id] || {};
        var lvl = n.RiskLevel || 'none';
        el.classList.toggle('is-dim', !!riskFilter && lvl !== riskFilter);
      });
    }
    function highlight(id) {
      if (hoverId === id) return;
      hoverId = id;
      var keep = {};
      if (id) {
        keep[id] = true;
        (geo.adj[id] || []).forEach(function (v) { keep[v] = true; });
      }
      Array.prototype.forEach.call(gNodes.querySelectorAll('.sm-topo-node'), function (el) {
        el.classList.toggle('is-dim', !!id && !keep[el.getAttribute('data-id')]);
      });
      Object.keys(edgeIndex).forEach(function (key) {
        var rec = edgeIndex[key];
        var on = id ? (rec.a === id || rec.b === id) : false;
        rec.grp.classList.toggle('is-dim', !!id && !on);
        rec.edge.classList.toggle('is-hover', !!id && on);
      });
      if (riskFilter) applyFilter();
    }

    /* ---------- 空态 / 遮罩 ---------- */
    function showEmpty() {
      elOverlay.innerHTML =
        '<div class="sm-empty" style="max-width:520px">' +
        '<div class="sm-empty-ico">' + ti('M4 6h16M4 12h16M4 18h16') + '</div>' +
        '<div class="sm-empty-title">尚未发现任何网络设备</div>' +
        '<div class="sm-empty-desc">StarMap 通过被动流量测绘自动生长拓扑。请先导入 PCAP 离线样本，或启动实时抓包采集内网流量。</div>' +
        '<div class="sm-empty-ops">' +
        '<a class="sm-btn is-primary" href="ingest.html">' + ti('M12 21V9m0 0 4 4m-4-4-4 4M4 7V5a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v2') + '导入 PCAP / 启动抓包</a>' +
        '<button class="sm-btn" data-act="topo-reload">重新加载拓扑</button>' +
        '</div></div>';
      elOverlay.classList.remove('sm-hide');
      elLegend.innerHTML = '';
    }
    function showOverlay(html) {
      elOverlay.innerHTML = html;
      elOverlay.classList.remove('sm-hide');
    }
    function hideOverlay() { elOverlay.classList.add('sm-hide'); elOverlay.innerHTML = ''; }

    /* ---------- 交互 ---------- */
    svg.addEventListener('wheel', function (e) {
      e.preventDefault();
      var r = svg.getBoundingClientRect();
      zoomAt(e.clientX - r.left, e.clientY - r.top, e.deltaY < 0 ? 1.12 : 1 / 1.12);
    }, { passive: false });

    svg.addEventListener('mousedown', function (e) {
      if (e.button === 2) return;
      var nodeEl = e.target.closest ? e.target.closest('.sm-topo-node') : null;
      drag = {
        x0: e.clientX, y0: e.clientY, tx0: tx, ty0: ty, moved: 0,
        node: nodeEl ? nodeEl.getAttribute('data-id') : null,
        nodeX0: nodeEl ? geo.xy[nodeEl.getAttribute('data-id')].x : 0,
        nodeY0: nodeEl ? geo.xy[nodeEl.getAttribute('data-id')].y : 0,
        shift: e.shiftKey || e.altKey, el: nodeEl
      };
      if (drag.shift && !nodeEl) svg.classList.add('is-selecting');
      else svg.classList.add('is-panning');
    });

    window.addEventListener('mousemove', function (e) {
      if (!drag) return;
      var dx = e.clientX - drag.x0, dy = e.clientY - drag.y0;
      drag.moved = Math.max(drag.moved, Math.abs(dx) + Math.abs(dy));
      if (drag.shift && !drag.node) {
        drawMarquee(drag.x0, drag.y0, e.clientX, e.clientY);
        return;
      }
      if (drag.node && drag.moved > 3) {
        var p = geo.xy[drag.node];
        p.x = drag.nodeX0 + dx / k;
        p.y = drag.nodeY0 + dy / k;
        drag.el.setAttribute('transform', 'translate(' + p.x.toFixed(1) + ',' + p.y.toFixed(1) + ')');
        Object.keys(edgeIndex).forEach(function (key) {
          var rec = edgeIndex[key];
          if (rec.a !== drag.node && rec.b !== drag.node) return;
          var d = edgeD(rec.a, rec.b);
          if (!d) return;
          rec.edge.setAttribute('d', d);
          if (rec.flow) rec.flow.setAttribute('d', d);
          rec.hit.setAttribute('d', d);
        });
        return;
      }
      tx = drag.tx0 + dx; ty = drag.ty0 + dy;
      applyTransform();
    });

    window.addEventListener('mouseup', function (e) {
      if (!drag) return;
      svg.classList.remove('is-panning', 'is-selecting');
      if (drag.shift && !drag.node && drag.moved > 4) {
        var g1 = toGraph(Math.min(drag.x0, e.clientX), Math.min(drag.y0, e.clientY));
        var g2 = toGraph(Math.max(drag.x0, e.clientX), Math.max(drag.y0, e.clientY));
        selected = {};
        Object.keys(geo.xy).forEach(function (id) {
          var p = geo.xy[id];
          if (p.x >= g1.x && p.x <= g2.x && p.y >= g1.y && p.y <= g2.y) selected[id] = true;
        });
        syncSelection();
        emit('select', Object.keys(selected));
      }
      clearMarquee();
      drag = null;
    });

    function drawMarquee(x0, y0, x1, y1) {
      var a = toGraph(Math.min(x0, x1), Math.min(y0, y1));
      var b = toGraph(Math.max(x0, x1), Math.max(y0, y1));
      var m = viewport.querySelector('.sm-topo-marquee');
      if (!m) {
        m = document.createElementNS(NS, 'rect');
        m.setAttribute('class', 'sm-topo-marquee');
        viewport.appendChild(m);
      }
      m.setAttribute('x', a.x.toFixed(1));
      m.setAttribute('y', a.y.toFixed(1));
      m.setAttribute('width', (b.x - a.x).toFixed(1));
      m.setAttribute('height', (b.y - a.y).toFixed(1));
    }
    function clearMarquee() {
      var m = viewport.querySelector('.sm-topo-marquee');
      if (m) m.remove();
    }

    svg.addEventListener('click', function (e) {
      var nodeEl = e.target.closest ? e.target.closest('.sm-topo-node') : null;
      if (nodeEl) {
        var id = nodeEl.getAttribute('data-id');
        selected = {}; selected[id] = true;
        syncSelection();
        emit('select', [id]);
        emit('nodeClick', { id: id, node: nodeIndex[id] });
        return;
      }
      var edgeEl = e.target.closest ? e.target.closest('[data-edge]') : null;
      if (edgeEl) {
        var rec = edgeIndex[edgeEl.getAttribute('data-edge')];
        if (rec) emit('edgeClick', { edge: rec.data, a: rec.a, b: rec.b });
        return;
      }
      selected = {};
      syncSelection();
      emit('select', []);
    });

    svg.addEventListener('dblclick', function (e) {
      var nodeEl = e.target.closest ? e.target.closest('.sm-topo-node') : null;
      if (!nodeEl) return;
      var id = nodeEl.getAttribute('data-id');
      emit('nodeDblClick', { id: id, node: nodeIndex[id] });
    });

    svg.addEventListener('contextmenu', function (e) {
      e.preventDefault();
      var nodeEl = e.target.closest ? e.target.closest('.sm-topo-node') : null;
      emit('contextMenu', {
        x: e.clientX, y: e.clientY,
        id: nodeEl ? nodeEl.getAttribute('data-id') : null,
        node: nodeEl ? nodeIndex[nodeEl.getAttribute('data-id')] : null
      });
    });

    svg.addEventListener('mouseover', function (e) {
      var nodeEl = e.target.closest ? e.target.closest('.sm-topo-node') : null;
      if (nodeEl) {
        var id = nodeEl.getAttribute('data-id');
        highlight(id);
        emit('nodeHover', { id: id, node: nodeIndex[id], x: e.clientX, y: e.clientY });
      } else {
        var eg = e.target.closest ? e.target.closest('[data-edge]') : null;
        if (eg) {
          var rec = edgeIndex[eg.getAttribute('data-edge')];
          if (rec) emit('edgeHover', { edge: rec.data, a: rec.a, b: rec.b, x: e.clientX, y: e.clientY });
        }
      }
    });
    svg.addEventListener('mouseleave', function () { highlight(null); emit('nodeHover', null); });

    elMini.addEventListener('mousedown', function (e) {
      var move = function (ev) { miniJump(ev); };
      var up = function () {
        window.removeEventListener('mousemove', move);
        window.removeEventListener('mouseup', up);
      };
      window.addEventListener('mousemove', move);
      window.addEventListener('mouseup', up);
      miniJump(e);
    });
    function miniJump(e) {
      var m = elMini.__m;
      if (!m) return;
      var r = elMini.getBoundingClientRect();
      var gx = ((e.clientX - r.left) * (176 / r.width) - m.ox) / m.sk;
      var gy = ((e.clientY - r.top) * (116 / r.height) - m.oy) / m.sk;
      var s = size();
      tx = s.w / 2 - gx * k;
      ty = s.h / 2 - gy * k;
      applyTransform();
    }

    wrap.querySelector('.sm-topo-tools').addEventListener('click', function (e) {
      var b = e.target.closest('[data-t]');
      if (!b) return;
      var t = b.getAttribute('data-t');
      if (t === 'zin') zoomBy(1.2);
      else if (t === 'zout') zoomBy(1 / 1.2);
      else if (t === 'fit') fit();
      else if (t === 'relayout') { render(); fit(); emit('relayout', null); }
    });

    function syncSelection() {
      Array.prototype.forEach.call(gNodes.querySelectorAll('.sm-topo-node'), function (el) {
        el.classList.toggle('is-sel', !!selected[el.getAttribute('data-id')]);
      });
    }

    /* ---------- 导出 ---------- */
    function exportSVGString() {
      if (!geo) return '';
      var b = bbox();
      var w = Math.ceil(b.w + PAD * 2), h = Math.ceil(b.h + PAD * 2);
      var clone = viewport.cloneNode(true);
      Array.prototype.forEach.call(clone.querySelectorAll('.sm-topo-node'), function (el) {
        el.classList.remove('is-dim');
      });
      Array.prototype.forEach.call(clone.querySelectorAll('.sm-topo-edge-grp'), function (el) {
        el.classList.remove('is-dim');
      });
      var marq = clone.querySelector('.sm-topo-marquee');
      if (marq) marq.remove();
      var inner = new XMLSerializer().serializeToString(clone);
      return '<svg xmlns="' + NS + '" width="' + w + '" height="' + h + '" viewBox="' +
        (b.x - PAD) + ' ' + (b.y - PAD) + ' ' + w + ' ' + h + '">' +
        '<style>' + EXPORT_CSS + '</style>' +
        '<rect x="' + (b.x - PAD) + '" y="' + (b.y - PAD) + '" width="' + w + '" height="' + h + '" fill="#ffffff"/>' +
        '<text class="sm-topo-title" x="' + (b.x - PAD + 24) + '" y="' + (b.y - PAD + 34) + '">StarMap 内网拓扑图</text>' +
        '<text class="sm-topo-meta" x="' + (b.x - PAD + 24) + '" y="' + (b.y - PAD + 52) + '">生成时间 ' +
        esc(new Date().toLocaleString('zh-CN', { hour12: false })) + ' · 节点 ' + (data.Nodes || []).length +
        ' · 链路 ' + (data.Edges || []).length + '</text>' +
        inner + '</svg>';
    }
    function download(name, href) {
      var a = document.createElement('a');
      a.href = href;
      a.download = name;
      document.body.appendChild(a);
      a.click();
      a.remove();
    }
    function stamp() {
      var d = new Date(), p = function (n) { return n < 10 ? '0' + n : '' + n; };
      return d.getFullYear() + p(d.getMonth() + 1) + p(d.getDate()) + '-' + p(d.getHours()) + p(d.getMinutes()) + p(d.getSeconds());
    }
    function exportSVG() {
      if (!(data.Nodes || []).length) { global.UI && global.UI.toast('拓扑尚未加载', 'err'); return; }
      var s = exportSVGString();
      var blob = new Blob([s], { type: 'image/svg+xml;charset=utf-8' });
      var url = URL.createObjectURL(blob);
      download('starmap-topology-' + stamp() + '.svg', url);
      setTimeout(function () { URL.revokeObjectURL(url); }, 4000);
    }
    function exportPNG() {
      if (!(data.Nodes || []).length) { global.UI && global.UI.toast('拓扑尚未加载', 'err'); return; }
      var s = exportSVGString();
      var img = new Image();
      var url = 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(s);
      img.onload = function () {
        var scale = 2;
        var cv = document.createElement('canvas');
        cv.width = img.width * scale;
        cv.height = img.height * scale;
        var ctx = cv.getContext('2d');
        ctx.fillStyle = '#ffffff';
        ctx.fillRect(0, 0, cv.width, cv.height);
        ctx.drawImage(img, 0, 0, cv.width, cv.height);
        try {
          download('starmap-topology-' + stamp() + '.png', cv.toDataURL('image/png'));
        } catch (e2) {
          global.UI && global.UI.toast('PNG 导出失败：' + e2.message, 'err');
        }
      };
      img.onerror = function () { global.UI && global.UI.toast('PNG 导出失败：图形序列化异常', 'err'); };
      img.src = url;
    }

    /* ---------- 对外 API ---------- */
    var api = {
      on: on,
      setData: function (d) {
        data = d || { Nodes: [], Edges: [] };
        selected = {}; hoverId = null;
        render();
        if ((data.Nodes || []).length) fit();
        return api;
      },
      setAlerts: function (map) { alerts = map || {}; render(); return api; },
      setRiskFilter: function (lv) { riskFilter = lv || ''; applyFilter(); return api; },
      getRiskFilter: function () { return riskFilter; },
      fit: fit,
      zoomIn: function () { zoomBy(1.2); },
      zoomOut: function () { zoomBy(1 / 1.2); },
      relayout: function () { render(); fit(); },
      centerOn: centerOn,
      select: function (ids) {
        selected = {};
        (ids || []).forEach(function (i) { selected[i] = true; });
        syncSelection();
      },
      getSelected: function () { return Object.keys(selected); },
      showOverlay: showOverlay,
      hideOverlay: hideOverlay,
      exportSVG: exportSVG,
      exportPNG: exportPNG,
      nodeCount: function () { return (data.Nodes || []).length; },
      edgeCount: function () { return (data.Edges || []).length; },
      resize: function () { applyTransform(); }
    };

    window.addEventListener('resize', function () { updateMiniView(); });
    render();
    return api;
  }

  SM.Topo = {
    create: create,
    glyph: function (t) { return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round">' + (GLYPH[t] || GLYPH.unknown) + '</svg>'; },
    typeLabel: function (t) { return TYPE_LABEL[t] || t; },
    riskColor: function (lv) { return RISK[lv] || RISK.none; }
  };
})(window);
