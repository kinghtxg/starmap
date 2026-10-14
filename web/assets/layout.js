/* StarMap 星图 V1.0 - 全局布局：左侧导航 + 低透明拓扑连线动态背景 + 通用 UI 工具 */
(function () {
  'use strict';

  const NAV = [
    { href: 'index.html', label: '拓扑总览', icon: 'M4 6h16M4 12h16M4 18h16' },
    { href: 'events.html', label: '风险事件', icon: 'M12 9v4m0 4h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z' },
    { href: 'whitelist.html', label: '白名单', icon: 'M9 12l2 2 4-4m5.6 2A9 9 0 1 1 12 3a9 9 0 0 1 8.6 9z' },
    { href: 'domains.html', label: '网络域', icon: 'M3 7h18M3 12h18M3 17h18' },
    { href: 'ingest.html', label: '数据接入', icon: 'M12 3v12m0 0 4-4m-4 4-4-4M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2' },
    { href: 'settings.html', label: '系统配置', icon: 'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm7-3a7 7 0 0 1-.1 1.2l2 1.6-2 3.4-2.4.9a7 7 0 0 1-2 1.2L14 21h-4l-.5-2.5a7 7 0 0 1-2-1.2l-2.4.9-2-3.4 2-1.6A7 7 0 0 1 5 12a7 7 0 0 1 .1-1.2l-2-1.6 2-3.4 2-1.6 2-3.4 2.4.9a7 7 0 0 1 2-1.2l2.4-.9 2 3.4-2 1.6a7 7 0 0 1 .1 1.2z' },
    { href: 'logs.html', label: '审计日志', icon: 'M9 12h6m-6 4h6M9 8h6M5 3h14a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2z' },
    { href: 'about.html', label: '关于', icon: 'M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0z' },
  ];

  function currentPage() {
    const p = location.pathname.split('/').pop();
    return p || 'index.html';
  }

  function injectSidebar() {
    const page = currentPage();
    const aside = document.createElement('aside');
    aside.className = 'fixed left-0 top-0 bottom-0 w-56 bg-card/95 border-r border-slate-700/60 flex flex-col z-40 backdrop-blur';
    aside.innerHTML =
      '<div class="px-5 py-5 border-b border-slate-700/60">' +
      '  <div class="text-xl font-bold text-accent tracking-widest">StarMap 星图</div>' +
      '  <div class="text-xs text-slate-400 mt-1">网内拓扑自动测绘引擎 V1.0</div>' +
      '</div>' +
      '<nav class="flex-1 py-3 overflow-y-auto">' +
      NAV.map(function (n) {
        const active = n.href === page;
        return '<a href="' + n.href + '" class="flex items-center gap-3 px-5 py-2.5 text-sm transition-colors ' +
          (active ? 'text-accent bg-accent/10 border-r-2 border-accent' : 'text-slate-300 hover:text-accent hover:bg-slate-700/30') + '">' +
          '<svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" stroke-width="1.8" viewBox="0 0 24 24" stroke-linecap="round" stroke-linejoin="round"><path d="' + n.icon + '"/></svg>' +
          '<span>' + n.label + '</span></a>';
      }).join('') +
      '</nav>' +
      '<div class="px-5 py-4 border-t border-slate-700/60 text-xs text-slate-500">极客星空实验室<br/>Apache-2.0</div>';
    document.body.prepend(aside);
  }

  /* ---- 低透明拓扑连线动态背景 ---- */
  function startBackground() {
    const canvas = document.createElement('canvas');
    canvas.id = 'bg-topo';
    canvas.style.cssText = 'position:fixed;inset:0;width:100%;height:100%;z-index:-1;opacity:.35;pointer-events:none';
    document.body.prepend(canvas);
    const ctx = canvas.getContext('2d');
    let W, H, nodes = [];
    const N = 40, LINK = 140;

    function resize() {
      W = canvas.width = innerWidth;
      H = canvas.height = innerHeight;
    }
    function init() {
      nodes = [];
      for (let i = 0; i < N; i++) {
        nodes.push({
          x: Math.random() * W, y: Math.random() * H,
          vx: (Math.random() - .5) * .35, vy: (Math.random() - .5) * .35,
          r: Math.random() * 1.6 + .8,
        });
      }
    }
    function tick() {
      ctx.clearRect(0, 0, W, H);
      for (const n of nodes) {
        n.x += n.vx; n.y += n.vy;
        if (n.x < 0 || n.x > W) n.vx *= -1;
        if (n.y < 0 || n.y > H) n.vy *= -1;
      }
      ctx.strokeStyle = 'rgba(56,189,248,.12)';
      ctx.lineWidth = .6;
      for (let i = 0; i < N; i++) for (let j = i + 1; j < N; j++) {
        const a = nodes[i], b = nodes[j];
        const d = Math.hypot(a.x - b.x, a.y - b.y);
        if (d < LINK) {
          ctx.globalAlpha = 1 - d / LINK;
          ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
        }
      }
      ctx.globalAlpha = 1;
      ctx.fillStyle = 'rgba(56,189,248,.5)';
      for (const n of nodes) { ctx.beginPath(); ctx.arc(n.x, n.y, n.r, 0, 7); ctx.fill(); }
      requestAnimationFrame(tick);
    }
    resize(); init(); tick();
    addEventListener('resize', () => { resize(); init(); });
  }

  /* ---- 通用 UI 工具 ---- */
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }
  function fmtTime(t) {
    if (!t) return '-';
    const d = new Date(t);
    return isNaN(d) ? String(t) : d.toLocaleString('zh-CN', { hour12: false });
  }
  function fmtBytes(n) {
    n = Number(n) || 0;
    const u = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return n.toFixed(i ? 1 : 0) + ' ' + u[i];
  }
  function toast(msg, type) {
    const colors = { ok: 'border-green-500/50 text-green-300', err: 'border-red-500/50 text-red-300', info: 'border-accent/50 text-accent' };
    const el = document.createElement('div');
    el.className = 'fixed top-5 right-5 z-50 px-4 py-2.5 rounded-lg bg-card border shadow-lg text-sm max-w-sm ' + (colors[type] || colors.info);
    el.textContent = msg;
    document.body.appendChild(el);
    setTimeout(() => { el.style.opacity = '0'; el.style.transition = 'opacity .4s'; setTimeout(() => el.remove(), 400); }, 3200);
  }
  function loadingHTML(text) {
    return '<div class="flex items-center gap-3 text-slate-400 py-10 justify-center text-sm">' +
      '<svg class="animate-spin w-5 h-5 text-accent" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"/><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 0 1 8-8v4a4 4 0 0 0-4 4H4z"/></svg>' +
      esc(text || '加载中…') + '</div>';
  }
  function emptyHTML(text, sub) {
    return '<div class="text-center py-14 text-slate-500">' +
      '<div class="text-4xl mb-3 opacity-40">◇</div>' +
      '<div class="text-sm">' + esc(text || '暂无数据') + '</div>' +
      (sub ? '<div class="text-xs mt-2 text-slate-600">' + esc(sub) + '</div>' : '') + '</div>';
  }
  function errorHTML(err) {
    return '<div class="text-center py-14">' +
      '<div class="text-red-400/70 text-sm">⚠ ' + esc(err && err.message ? err.message : String(err)) + '</div>' +
      '<div class="text-xs text-slate-500 mt-2">后端服务不可达时展示空态，请确认 StarMap 服务已启动后重试。</div>' +
      '<button onclick="location.reload()" class="mt-4 px-4 py-1.5 text-xs rounded bg-accent/20 text-accent hover:bg-accent/30 border border-accent/40">重试</button>' +
      '</div>';
  }
  function riskColor(level) {
    return { high: '#F87171', mid: '#FB923C', low: '#4ADE80', none: '#38BDF8' }[level] || '#38BDF8';
  }
  function riskLabel(level) {
    return { high: '高风险', mid: '中风险', low: '低风险', none: '正常' }[level] || level || '正常';
  }
  function riskBadge(level) {
    const c = riskColor(level);
    return '<span class="inline-flex items-center gap-1.5 text-xs" style="color:' + c + '">' +
      '<span class="w-2 h-2 rounded-full" style="background:' + c + '"></span>' + riskLabel(level) + '</span>';
  }

  window.UI = { esc, fmtTime, fmtBytes, toast, loadingHTML, emptyHTML, errorHTML, riskColor, riskLabel, riskBadge };

  document.addEventListener('DOMContentLoaded', () => { injectSidebar(); startBackground(); });
})();
