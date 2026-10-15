/* ==========================================================================
   StarMap 星图 V1.1 —— 共享前端工具（app.js）
   零依赖原生实现：转义 / 事件委托 / 统一导航 / 模态 / 抽屉 / 分页 / 加载态 / Toast
   安全：全面使用事件委托 + data-* 传参，禁止 JSON.stringify 拼 onclick（存储型 XSS）
   ========================================================================== */
(function (global) {
  'use strict';

  /* ---------- 图标（内联 SVG，线条风格，无图标字体/无 CDN） ---------- */
  var ICONS = {
    topo: 'M4 6h16M4 12h16M4 18h16',
    alert: 'M12 9v4m0 4h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z',
    shield: 'M9 12l2 2 4-4m5.6 2A9 9 0 1 1 12 3a9 9 0 0 1 8.6 9z',
    domain: 'M3 7h18M3 12h18M3 17h18',
    ingest: 'M12 3v12m0 0 4-4m-4 4-4-4M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2',
    settings: 'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm7-3a7 7 0 0 1-.1 1.2l2 1.6-2 3.4-2.4.9a7 7 0 0 1-2 1.2L14 21h-4l-.5-2.5a7 7 0 0 1-2-1.2l-2.4.9-2-3.4 2-1.6A7 7 0 0 1 5 12a7 7 0 0 1 .1-1.2l-2-1.6 2-3.4 2-1.6 2-3.4 2.4.9a7 7 0 0 1 2-1.2l2.4-.9 2 3.4-2 1.6a7 7 0 0 1 .1 1.2z',
    logs: 'M9 12h6m-6 4h6M9 8h6M5 3h14a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2z',
    about: 'M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0z',
    plus: 'M12 5v14M5 12h14',
    refresh: 'M20 11a8 8 0 1 0-2.3 6M20 5v6h-6',
    search: 'M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14zm5.5-1.5L21 21',
    download: 'M12 3v12m0 0 4-4m-4 4-4-4M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2',
    upload: 'M12 21V9m0 0 4 4m-4-4-4 4M4 7V5a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v2',
    back: 'M10 19l-7-7 7-7M3 12h18',
    close: 'M6 6l12 12M18 6L6 18',
    check: 'M4 12.5 9 17.5 20 6.5',
    edit: 'M4 20h4L20 8l-4-4L4 16v4z',
    trash: 'M4 7h16M9 7V5h6v2M6 7l1 13h10l1-13M10 11v6M14 11v6',
    layout: 'M4 4h6v6H4V4zm10 0h6v6h-6V4zM4 14h6v6H4v-6zm10 0h6v6h-6v-6z',
    zoomin: 'M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14zm5.5-1.5L21 21M8.5 11h5M11 8.5v5',
    zoomout: 'M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14zm5.5-1.5L21 21M8.5 11h5',
    fit: 'M4 9V5a1 1 0 0 1 1-1h4M20 9V5a1 1 0 0 0-1-1h-4M4 15v4a1 1 0 0 0 1 1h4M20 15v4a1 1 0 0 1-1 1h-4',
    filter: 'M3 5h18l-7 8v6l-4-2v-4L3 5z',
    play: 'M7 4.5v15l13-7.5-13-7.5z',
    stop: 'M6.5 6.5h11v11h-11z',
    target: 'M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zm0-4.5a4.5 4.5 0 1 0 0-9 4.5 4.5 0 0 0 0 9zm0-3.5a1 1 0 1 0 0-2 1 1 0 0 0 0 2z',
    info: 'M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zm0-13h.01M11 12h1v5h1',
    copy: 'M9 9h10v10H9V9zM5 15V5h10',
    drill: 'M12 5v10m0 0 4-4m-4 4-4-4M4 19h16',
    clock: 'M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zm0-13v5l3.5 2',
    node: 'M12 3v6m0 0-4 4m4-4 4 4M5 21h14a2 2 0 0 0 2-2v-3a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v3a2 2 0 0 0 2 2z',
    link: 'M9 15l6-6M10 6l1-1a4 4 0 0 1 6 6l-1 1M14 18l-1 1a4 4 0 0 1-6-6l1-1',
    warn: 'M12 9v4m0 4h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z',
    inbox: 'M3 12h5l1.5 3h5L16 12h5M3 12l2.5-7h13L21 12v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-6z',
    asset: 'M5 3h14a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2zm2 4h2v2H7V7zm4 0h2v2h-2V7zM7 12h2v2H7v-2zm4 0h2v2h-2v-2zm4 0h2v2h-2v-2z',
    port: 'M12 4a8 8 0 0 0-8 8v1M4 13v2m0 0v3a1 1 0 0 0 1 1h1m0 0h12m0 0h1a1 1 0 0 0 1-1v-3m-2 0v-2a8 8 0 0 0-8-8'
  };

  function ico(name, cls) {
    var d = ICONS[name] || ICONS.info;
    return '<svg class="' + (cls || '') + '" viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
      'stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="' + d + '"/></svg>';
  }

  /* ---------- 转义 ---------- */
  var ESC_MAP = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
  function esc(s) {
    return String(s === null || s === undefined ? '' : s).replace(/[&<>"']/g, function (c) { return ESC_MAP[c]; });
  }
  /** 用于属性值：额外转义反斜杠与换行，避免 attribute 注入 */
  function escAttr(s) {
    return esc(s).replace(/[\r\n\t]/g, ' ').replace(/\\/g, '&#92;');
  }

  /* ---------- 格式化 ---------- */
  function pad(n) { return n < 10 ? '0' + n : String(n); }
  function fmtTime(t) {
    if (!t) return '-';
    var d = new Date(t);
    if (isNaN(d.getTime())) return esc(t);
    return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + ' ' +
      pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
  }
  function fmtTimeShort(t) {
    if (!t) return '-';
    var d = new Date(t);
    if (isNaN(d.getTime())) return esc(t);
    return pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes());
  }
  function fmtBytes(n) {
    n = Number(n) || 0;
    var u = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'], i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return (i === 0 ? String(Math.round(n)) : n.toFixed(1)) + ' ' + u[i];
  }
  function fmtNum(n) {
    if (n === null || n === undefined || n === '') return '-';
    return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  }
  function fmtAgo(t) {
    if (!t) return '-';
    var d = new Date(t);
    if (isNaN(d.getTime())) return '-';
    var s = (Date.now() - d.getTime()) / 1000;
    if (s < 60) return Math.max(0, Math.floor(s)) + ' 秒前';
    if (s < 3600) return Math.floor(s / 60) + ' 分钟前';
    if (s < 86400) return Math.floor(s / 3600) + ' 小时前';
    return Math.floor(s / 86400) + ' 天前';
  }

  /* ---------- 风险等级 ---------- */
  var RISK_LABEL = { high: '高风险', mid: '中风险', low: '低风险', none: '正常' };
  function riskLabel(lv) { return RISK_LABEL[lv] || lv || '正常'; }
  function riskTag(lv) {
    var k = RISK_LABEL[lv] ? lv : 'none';
    return '<span class="sm-risk-tag ' + escAttr(k) + '">' + esc(riskLabel(lv)) + '</span>';
  }
  function riskText(lv) {
    var k = RISK_LABEL[lv] ? lv : 'none';
    return '<span class="sm-risk sm-risk-' + escAttr(k) + '">' + esc(riskLabel(lv)) + '</span>';
  }

  /* ---------- Toast ---------- */
  var toastBox = null;
  function toast(msg, type) {
    if (!toastBox) {
      toastBox = document.createElement('div');
      toastBox.className = 'sm-toasts';
      document.body.appendChild(toastBox);
    }
    var kind = type === 'ok' ? 'is-ok' : type === 'err' ? 'is-err' : type === 'warn' ? 'is-warn' : '';
    var icoName = type === 'ok' ? 'check' : type === 'err' ? 'warn' : type === 'warn' ? 'warn' : 'info';
    var el = document.createElement('div');
    el.className = 'sm-toast ' + kind;
    el.innerHTML = '<span class="sm-toast-ico">' + ico(icoName) + '</span><span class="sm-toast-msg"></span>';
    el.querySelector('.sm-toast-msg').textContent = String(msg === undefined || msg === null ? '' : msg);
    toastBox.appendChild(el);
    var timer = setTimeout(close, type === 'err' ? 4200 : 3000);
    el.addEventListener('click', close);
    function close() {
      clearTimeout(timer);
      el.classList.add('is-out');
      setTimeout(function () { if (el.parentNode) el.parentNode.removeChild(el); }, 200);
    }
    return close;
  }

  /* ---------- 事件委托（替代内联 onclick，杜绝 XSS） ---------- */
  var ACTS = {};
  var MENU_CTX = {};
  var menuSeq = 0;

  function on(act, fn) { ACTS[act] = fn; }
  function off(act) { delete ACTS[act]; }

  document.addEventListener('click', function (e) {
    var el = e.target.closest ? e.target.closest('[data-act]') : null;
    if (!el) return;
    var fn = ACTS[el.getAttribute('data-act')];
    if (!fn) return;
    fn(el, e, MENU_CTX[el.getAttribute('data-mid')]);
  });

  /* ---------- 模态框 ---------- */
  function modal(opts) {
    opts = opts || {};
    var mask = document.createElement('div');
    mask.className = 'sm-mask';
    mask.innerHTML =
      '<div class="sm-modal" role="dialog" aria-modal="true"' + (opts.width ? ' style="width:' + escAttr(opts.width) + 'px"' : '') + '>' +
      '<div class="sm-modal-hd"><h3 class="sm-modal-title"></h3>' +
      '<button class="sm-modal-close" data-act="sm-modal-close" aria-label="关闭">&times;</button></div>' +
      '<div class="sm-modal-bd"></div>' +
      '<div class="sm-modal-ft">' +
      '<button class="sm-btn" data-act="sm-modal-cancel">取消</button>' +
      '<button class="sm-btn is-primary" data-act="sm-modal-ok"><span class="sm-btn-ico">确定</span><i class="sm-spin"></i></button>' +
      '</div></div>';
    mask.querySelector('.sm-modal-title').textContent = opts.title || '提示';
    var bd = mask.querySelector('.sm-modal-bd');
    if (typeof opts.body === 'string') bd.innerHTML = opts.body;
    else if (opts.body) bd.appendChild(opts.body);
    var okBtn = mask.querySelector('[data-act="sm-modal-ok"]');
    var cancelBtn = mask.querySelector('[data-act="sm-modal-cancel"]');
    okBtn.querySelector('.sm-btn-ico').textContent = opts.okText || '确定';
    cancelBtn.textContent = opts.cancelText || '取消';
    if (opts.danger) { okBtn.classList.remove('is-primary'); okBtn.classList.add('is-danger'); }
    if (opts.hideCancel) cancelBtn.classList.add('sm-hide');

    document.body.appendChild(mask);
    requestAnimationFrame(function () { mask.classList.add('is-open'); });

    var api = {
      el: mask,
      body: bd,
      close: function () {
        mask.classList.remove('is-open');
        setTimeout(function () { if (mask.parentNode) mask.parentNode.removeChild(mask); }, 200);
      },
      busy: function (b) { okBtn.classList.toggle('is-loading', !!b); }
    };

    mask.addEventListener('click', function (e) {
      if (e.target === mask) { api.close(); return; }
      var el = e.target.closest('[data-act]');
      if (!el) return;
      var a = el.getAttribute('data-act');
      if (a === 'sm-modal-close' || a === 'sm-modal-cancel') { api.close(); return; }
      if (a === 'sm-modal-ok') {
        if (!opts.onOk) { api.close(); return; }
        var r = opts.onOk(api, bd);
        if (r && typeof r.then === 'function') {
          api.busy(true);
          r.then(function (v) { api.busy(false); if (v !== false) api.close(); },
            function (err) { api.busy(false); toast(err && err.message ? err.message : String(err), 'err'); });
        } else if (r !== false) {
          api.close();
        }
      }
    });
    if (opts.onOpen) opts.onOpen(api, bd);
    setTimeout(function () {
      var f = bd.querySelector('input,select,textarea');
      if (f && !opts.noFocus) f.focus();
    }, 220);
    return api;
  }

  function confirm(opts) {
    opts = opts || {};
    return new Promise(function (resolve) {
      var done = false;
      modal({
        title: opts.title || '确认操作',
        body: '<div style="font-size:13px;line-height:1.7">' + (opts.content || '') + '</div>',
        okText: opts.okText || '确定',
        danger: opts.danger !== false,
        onOk: function () { done = true; resolve(true); },
        onOpen: function (api) {
          var m = api.el.querySelector('.sm-mask') || api.el;
          m.__resolve = resolve;
        }
      });
      // 关闭（取消/遮罩/×）同样要 resolve，避免悬空 Promise
      var mask = document.querySelectorAll('.sm-mask');
      var last = mask[mask.length - 1];
      last.addEventListener('click', function (e) {
        var el = e.target.closest('[data-act]');
        var a = el && el.getAttribute('data-act');
        if (a === 'sm-modal-close' || a === 'sm-modal-cancel' || (!el && e.target === last)) {
          setTimeout(function () { if (!done) resolve(false); }, 0);
        }
      });
    });
  }

  /* ---------- 抽屉 ---------- */
  function openDrawer(id) {
    var d = document.getElementById(id);
    if (d) d.classList.add('is-open');
    var m = document.getElementById(id + '-mask');
    if (m) m.classList.add('is-open');
  }
  function closeDrawer(id) {
    var d = document.getElementById(id);
    if (d) d.classList.remove('is-open');
    var m = document.getElementById(id + '-mask');
    if (m) m.classList.remove('is-open');
  }

  /* ---------- 浮层提示 ---------- */
  var tipEl = null;
  var tip = {
    show: function (html, x, y) {
      if (!tipEl) {
        tipEl = document.createElement('div');
        tipEl.className = 'sm-tip';
        document.body.appendChild(tipEl);
      }
      tipEl.innerHTML = html;
      tipEl.classList.add('is-on');
      var r = tipEl.getBoundingClientRect();
      var left = x + 14, top = y + 14;
      if (left + r.width > window.innerWidth - 8) left = x - r.width - 14;
      if (top + r.height > window.innerHeight - 8) top = y - r.height - 14;
      tipEl.style.left = Math.max(8, left) + 'px';
      tipEl.style.top = Math.max(8, top) + 'px';
    },
    hide: function () { if (tipEl) tipEl.classList.remove('is-on'); }
  };

  /* ---------- 右键菜单 ---------- */
  var menuEl = null;
  function menu(x, y, items, ctx) {
    closeMenu();
    menuEl = document.createElement('div');
    menuEl.className = 'sm-menu';
    items.forEach(function (it) {
      if (!it) return;
      if (it.sep) {
        var s = document.createElement('div');
        s.className = 'sm-menu-sep';
        menuEl.appendChild(s);
        return;
      }
      var mid = 'm' + (++menuSeq);
      MENU_CTX[mid] = ctx;
      var el = document.createElement('div');
      el.className = 'sm-menu-item' + (it.danger ? ' is-danger' : '');
      el.setAttribute('data-act', it.act);
      el.setAttribute('data-mid', mid);
      if (it.disabled) el.setAttribute('disabled', '');
      el.innerHTML = ico(it.icon || 'info') + '<span></span>';
      el.querySelector('span').textContent = it.label;
      menuEl.appendChild(el);
    });
    document.body.appendChild(menuEl);
    var r = menuEl.getBoundingClientRect();
    menuEl.style.left = Math.max(6, Math.min(x, window.innerWidth - r.width - 6)) + 'px';
    menuEl.style.top = Math.max(6, Math.min(y, window.innerHeight - r.height - 6)) + 'px';
    setTimeout(function () {
      document.addEventListener('mousedown', onDocDown);
      window.addEventListener('blur', closeMenu);
    }, 0);
  }
  function onDocDown(e) { if (menuEl && !menuEl.contains(e.target)) closeMenu(); }
  function closeMenu() {
    if (menuEl) { if (menuEl.parentNode) menuEl.parentNode.removeChild(menuEl); menuEl = null; }
    document.removeEventListener('mousedown', onDocDown);
    window.removeEventListener('blur', closeMenu);
  }

  /* ---------- 状态片段 ---------- */
  function loadingHTML(text) {
    return '<div class="sm-loading"><i class="sm-spin"></i>' + esc(text || '加载中…') + '</div>';
  }
  function skeletonRows(n) {
    var s = '';
    for (var i = 0; i < (n || 5); i++) {
      s += '<div class="sm-skeleton-row">' +
        '<div class="sm-skeleton sm-skel-dot"></div>' +
        '<div class="sm-skeleton" style="flex:2;height:10px"></div>' +
        '<div class="sm-skeleton" style="flex:1;height:10px"></div>' +
        '<div class="sm-skeleton" style="flex:1;height:10px"></div></div>';
    }
    return s;
  }
  function emptyHTML(text, sub, ops) {
    return '<div class="sm-empty">' +
      '<div class="sm-empty-ico">' + ico('inbox') + '</div>' +
      '<div class="sm-empty-title">' + esc(text || '暂无数据') + '</div>' +
      (sub ? '<div class="sm-empty-desc">' + esc(sub) + '</div>' : '') +
      (ops ? '<div class="sm-empty-ops">' + ops + '</div>' : '') + '</div>';
  }
  function errorHTML(err) {
    var msg = err && err.message ? err.message : String(err || '未知错误');
    return '<div class="sm-empty">' +
      '<div class="sm-empty-ico" style="color:#e34d59">' + ico('warn') + '</div>' +
      '<div class="sm-empty-title" style="color:#a32a35">' + esc(msg) + '</div>' +
      '<div class="sm-empty-desc">后端服务不可达时展示空态，请确认 StarMap 服务已启动后重试。</div>' +
      '<div class="sm-empty-ops"><button class="sm-btn" data-act="sm-reload">重新加载</button></div></div>';
  }
  on('sm-reload', function () { location.reload(); });

  /* ---------- 分页 ---------- */
  function pagerHTML(total, page, size, act) {
    act = act || 'sm-page';
    var pages = Math.max(1, Math.ceil(total / size));
    var cur = Math.min(Math.max(1, page), pages);
    var list = [];
    if (pages <= 7) { for (var i = 1; i <= pages; i++) list.push(i); }
    else {
      list.push(1);
      if (cur > 3) list.push('…');
      for (var j = Math.max(2, cur - 1); j <= Math.min(pages - 1, cur + 1); j++) list.push(j);
      if (cur < pages - 2) list.push('…');
      list.push(pages);
    }
    var h = '<div class="sm-pager"><span style="margin-right:auto">共 ' + fmtNum(total) + ' 条 / ' + pages + ' 页</span>';
    h += '<button class="sm-pg" data-act="' + escAttr(act) + '" data-page="' + (cur - 1) + '"' + (cur <= 1 ? ' disabled' : '') + '>&lsaquo;</button>';
    list.forEach(function (p) {
      if (p === '…') { h += '<span class="sm-pg" style="border:none;background:none">…</span>'; return; }
      h += '<button class="sm-pg' + (p === cur ? ' is-cur' : '') + '" data-act="' + escAttr(act) + '" data-page="' + p + '">' + p + '</button>';
    });
    h += '<button class="sm-pg" data-act="' + escAttr(act) + '" data-page="' + (cur + 1) + '"' + (cur >= pages ? ' disabled' : '') + '>&rsaquo;</button>';
    return h + '</div>';
  }

  /* ---------- 数字滚动 ---------- */
  var REDUCED = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  function countTo(el, target, dur) {
    if (!el) return;
    var from = parseFloat(String(el.textContent).replace(/[^\d.\-]/g, '')) || 0;
    var to = Number(target) || 0;
    if (REDUCED || from === to) { el.textContent = fmtNum(to); return; }
    var d = dur || 520, t0 = performance.now();
    function step(t) {
      var k = Math.min(1, (t - t0) / d);
      var e = 1 - Math.pow(1 - k, 3);
      el.textContent = fmtNum(Math.round(from + (to - from) * e));
      if (k < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }

  /* ---------- 按钮忙碌态 ---------- */
  function busy(btn, on_) {
    if (!btn) return;
    if (on_) {
      btn.__txt = btn.innerHTML;
      btn.classList.add('is-loading');
      btn.insertAdjacentHTML('beforeend', '<i class="sm-spin"></i>');
      btn.disabled = true;
    } else {
      btn.classList.remove('is-loading');
      btn.disabled = false;
      var s = btn.querySelector('.sm-spin');
      if (s) s.remove();
    }
  }

  /* ---------- 复制 ---------- */
  function copy(text) {
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(function () { toast('已复制到剪贴板', 'ok'); });
        return;
      }
    } catch (_) { /* 降级 */ }
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.style.cssText = 'position:fixed;opacity:0';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); toast('已复制到剪贴板', 'ok'); } catch (_) { toast('复制失败', 'err'); }
    ta.remove();
  }

  /* ---------- 统一导航 ---------- */
  var NAV = [
    { href: 'index.html', label: '拓扑总览', icon: 'topo', group: '测绘' },
    { href: 'assets.html', label: '主机资产', icon: 'asset', group: '测绘' },
    { href: 'events.html', label: '风险事件', icon: 'alert', group: '测绘' },
    { href: 'whitelist.html', label: '白名单', icon: 'shield', group: '测绘' },
    { href: 'domains.html', label: '网络域', icon: 'domain', group: '测绘' },
    { href: 'ingest.html', label: '数据接入', icon: 'ingest', group: '运维' },
    { href: 'settings.html', label: '系统配置', icon: 'settings', group: '运维' },
    { href: 'logs.html', label: '审计日志', icon: 'logs', group: '运维' },
    { href: 'about.html', label: '关于', icon: 'about', group: '运维' }
  ];

  function currentPage() {
    var p = location.pathname.split('/').pop();
    return p || 'index.html';
  }

  function renderSider() {
    var host = document.getElementById('smSider');
    if (!host) return;
    var page = currentPage();
    var html =
      '<div class="sm-sider-brand">' +
      '<div class="sm-sider-logo"><svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" ' +
      'stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 6h16M4 12h16M4 18h16"/></svg></div>' +
      '<div><div class="sm-sider-name">StarMap 星图</div><div class="sm-sider-ver">内网拓扑引擎 V1.1</div></div></div>' +
      '<nav class="sm-sider-nav">';
    var g = '';
    NAV.forEach(function (n) {
      if (n.group !== g) { g = n.group; html += '<div class="sm-sider-group">' + esc(g) + '</div>'; }
      html += '<a class="sm-navitem' + (n.href === page ? ' is-active' : '') + '" href="' + n.href + '">' +
        ico(n.icon) + '<span>' + esc(n.label) + '</span></a>';
    });
    html += '</nav><div class="sm-sider-foot">极客星空实验室<br/>Apache-2.0 · 内网离线部署</div>';
    host.innerHTML = html;
  }

  /* ---------- 启动 ---------- */
  var UI = {
    ico: ico, ICONS: ICONS,
    esc: esc, escAttr: escAttr,
    fmtTime: fmtTime, fmtTimeShort: fmtTimeShort, fmtBytes: fmtBytes, fmtNum: fmtNum, fmtAgo: fmtAgo,
    riskLabel: riskLabel, riskTag: riskTag, riskText: riskText,
    toast: toast, modal: modal, confirm: confirm,
    openDrawer: openDrawer, closeDrawer: closeDrawer,
    tip: tip, menu: menu, closeMenu: closeMenu,
    loadingHTML: loadingHTML, skeletonRows: skeletonRows, emptyHTML: emptyHTML, errorHTML: errorHTML,
    pagerHTML: pagerHTML, countTo: countTo, busy: busy, copy: copy,
    on: on, off: off,
    renderSider: renderSider, NAV: NAV,
    reducedMotion: REDUCED
  };

  global.UI = UI;

  function decorateIcons() {
    var list = document.querySelectorAll('[data-ico]');
    Array.prototype.forEach.call(list, function (el) {
      if (el.querySelector('svg')) return;
      el.insertAdjacentHTML('afterbegin', ico(el.getAttribute('data-ico')));
    });
  }

  document.addEventListener('DOMContentLoaded', function () {
    renderSider();
    decorateIcons();
    // 全局：ESC 关闭浮层
    document.addEventListener('keydown', function (e) {
      if (e.key !== 'Escape') return;
      closeMenu();
      tip.hide();
      var m = document.querySelector('.sm-mask.is-open');
      if (m) m.classList.remove('is-open'), setTimeout(function () { m.remove(); }, 200);
      document.querySelectorAll('.sm-drawer.is-open').forEach(function (d) { closeDrawer(d.id); });
    });
  });
})(window);
