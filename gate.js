/* 哈佛皮肤管理 · 课程访问验证（模板）
 * 由 install_gate.py 生成 哈佛皮肤管理/gate.js 并内联注入全部 HTML。
 *
 * 设计要点：
 *  1. 凭据以 SHA-256 哈希保存，源码中不出现明文姓名/邮箱；
 *  2. 一次验证后写入 localStorage，本站任意页面、之后任何时间都无需再输入；
 *  3. 本地 file:// 打开时部分浏览器按文件隔离 localStorage，
 *     因此解锁后会给站内链接自动附带通行凭证 ?wbk=...，新页面读到后自行记住；
 *  4. 纯 JS SHA-256，不依赖 crypto.subtle，file:// / https 均可运行；
 *  5. 门禁为静态站点前端校验，可阻止常规未授权访问，但不等于服务端鉴权。
 */
(function () {
  'use strict';

  var SALT = 'harvard-skin-care-gate-v1';
  var USERS = ["26d47b772faa87f0b0422a1ee3fab9dc35938cf266f3cea2fd3d16b1b6ffa593"];              /* 授权凭据哈希数组，勿手工编辑 */
  var STORE_KEY = 'wb_gate_v1';
  var URL_KEY = 'wbk';
  var LINK_REWRITE = true; /* 是否给站内链接附凭证 */
  var root = document.documentElement;

  /* ---------------- 纯 JS SHA-256（UTF-8） ---------------- */
  var K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];
  function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }
  function utf8Bytes(s) {
    var out = [], i, c, c2, cp;
    for (i = 0; i < s.length; i++) {
      c = s.charCodeAt(i);
      if (c < 0x80) out.push(c);
      else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 63));
      else if (c < 0xd800 || c >= 0xe000)
        out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
      else {
        i++; c2 = s.charCodeAt(i) || 0;
        cp = 0x10000 + (((c & 0x3ff) << 10) | (c2 & 0x3ff));
        out.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 63),
                 0x80 | ((cp >> 6) & 63), 0x80 | (cp & 63));
      }
    }
    return out;
  }
  function sha256Hex(str) {
    var bytes = utf8Bytes(String(str));
    var bitLen = bytes.length * 8;
    bytes.push(0x80);
    while (bytes.length % 64 !== 56) bytes.push(0);
    var hi = Math.floor(bitLen / 0x100000000), lo = bitLen >>> 0;
    bytes.push((hi >>> 24) & 255, (hi >>> 16) & 255, (hi >>> 8) & 255, hi & 255,
               (lo >>> 24) & 255, (lo >>> 16) & 255, (lo >>> 8) & 255, lo & 255);
    var H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
             0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    var w = new Array(64), i, t;
    for (i = 0; i < bytes.length; i += 64) {
      for (t = 0; t < 16; t++) {
        var j = i + t * 4;
        w[t] = (bytes[j] << 24) | (bytes[j + 1] << 16) | (bytes[j + 2] << 8) | bytes[j + 3];
      }
      for (t = 16; t < 64; t++) {
        var s0 = rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >>> 3);
        var s1 = rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >>> 10);
        w[t] = (w[t - 16] + s0 + w[t - 7] + s1) >>> 0;
      }
      var a = H[0], b = H[1], c = H[2], d = H[3],
          e = H[4], f = H[5], g = H[6], h = H[7];
      for (t = 0; t < 64; t++) {
        var S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        var ch = (e & f) ^ ((~e) & g);
        var t1 = (h + S1 + ch + K[t] + w[t]) >>> 0;
        var S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        var maj = (a & b) ^ (a & c) ^ (b & c);
        var t2 = (S0 + maj) >>> 0;
        h = g; g = f; f = e; e = (d + t1) >>> 0;
        d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0;
      H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
      H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0;
      H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
    }
    var out = '';
    for (i = 0; i < 8; i++) out += ('00000000' + H[i].toString(16)).slice(-8);
    return out;
  }

  /* ---------------- 凭据 ---------------- */
  function normName(v) { return String(v || '').trim().toLowerCase().replace(/\s+/g, ' '); }
  function normEmail(v) { return String(v || '').trim().toLowerCase().replace(/\s+/g, ''); }
  function userHash(n, e) { return sha256Hex(SALT + '|' + normName(n) + '|' + normEmail(e)); }
  function tokenOf(h) { return sha256Hex('wb-gate-token|' + h); }
  function validToken(t) {
    if (!t) return false;
    t = String(t);
    for (var i = 0; i < USERS.length; i++) if (tokenOf(USERS[i]) === t) return true;
    return false;
  }

  /* ---------------- 通行状态 ---------------- */
  function readStore() {
    var v = null;
    try { v = localStorage.getItem(STORE_KEY); } catch (e) {}
    if (!v) { try { v = sessionStorage.getItem(STORE_KEY); } catch (e) {} }
    return v;
  }
  function writeStore(t) {
    try { localStorage.setItem(STORE_KEY, t); } catch (e) {}
    try { sessionStorage.setItem(STORE_KEY, t); } catch (e) {}
  }
  function urlToken() {
    try {
      var m = new RegExp('[?&]' + URL_KEY + '=([^&#]*)').exec(location.search || '');
      return m ? decodeURIComponent(m[1]) : null;
    } catch (e) { return null; }
  }
  function cleanUrl() {
    try {
      var u = new URL(location.href);
      if (u.searchParams.has(URL_KEY)) {
        u.searchParams.delete(URL_KEY);
        history.replaceState(null, '', u.href);
      }
    } catch (e) {}
  }

  /* ---------------- 遮罩 ---------------- */
  var overlay = null;
  function lock() {
    if (root && root.classList) root.classList.add('wb-gate-locked');
    try { document.body.style.overflow = 'hidden'; } catch (e) {}
  }
  function release() {
    if (root && root.classList) root.classList.remove('wb-gate-locked');
    try { document.body.style.overflow = ''; } catch (e) {}
    if (overlay && overlay.parentNode) overlay.parentNode.removeChild(overlay);
    overlay = null;
  }
  function showOverlay() {
    overlay = document.createElement('div');
    overlay.id = 'wb-gate-overlay';
    overlay.setAttribute('role', 'dialog');
    overlay.setAttribute('aria-modal', 'true');
    overlay.innerHTML =
      '<div class="wb-gate-card">' +
      '  <div class="wb-gate-brand">哈佛皮肤管理</div>' +
      '  <div class="wb-gate-en">HARVARD SKIN CARE AND REPAIR</div>' +
      '  <h1>课程访问验证</h1>' +
      '  <p class="wb-gate-desc">请输入报名时登记的<strong>姓名</strong>与<strong>邮箱</strong>，验证通过后即可浏览全部课程内容。</p>' +
      '  <form id="wb-gate-form" novalidate autocomplete="off">' +
      '    <label for="wb-gate-name">姓名 <span>Name</span></label>' +
      '    <input id="wb-gate-name" type="text" inputmode="text" placeholder="例如：CHEN PEI SHAN" autocomplete="name">' +
      '    <label for="wb-gate-email">邮箱 <span>Email</span></label>' +
      '    <input id="wb-gate-email" type="text" inputmode="email" placeholder="例如：name@example.com" autocomplete="email">' +
      '    <div id="wb-gate-error" class="wb-gate-error" hidden>姓名或邮箱不匹配，请核对后重试。</div>' +
      '    <button type="submit">进入课程 <span>Enter Course</span></button>' +
      '  </form>' +
      '  <p class="wb-gate-foot">只需验证一次，之后打开本站任意页面都不必再输入。</p>' +
      '</div>';
    (root || document.body || document).appendChild(overlay);

    var form = overlay.querySelector('#wb-gate-form');
    var nameEl = overlay.querySelector('#wb-gate-name');
    var mailEl = overlay.querySelector('#wb-gate-email');
    var errEl = overlay.querySelector('#wb-gate-error');
    form.addEventListener('submit', function (ev) {
      ev.preventDefault();
      var h = userHash(nameEl.value, mailEl.value);
      if (USERS.indexOf(h) >= 0) {
        writeStore(tokenOf(h));
        cleanUrl();
        release();
        installLinks();
      } else {
        errEl.hidden = false;
        mailEl.focus();
      }
    });
    nameEl.addEventListener('input', function () { errEl.hidden = true; });
    mailEl.addEventListener('input', function () { errEl.hidden = true; });
    setTimeout(function () { try { nameEl.focus(); } catch (e) {} }, 30);
  }

  /* ---------------- 站内链接自动携带凭证（本地 file:// 兜底） ---------------- */
  function installLinks() {
    if (!LINK_REWRITE) return;
    var t = readStore() || urlToken();
    if (!validToken(t)) return;
    function decorate() {
      var as = document.querySelectorAll('a[href]');
      for (var i = 0; i < as.length; i++) {
        var a = as[i], href = a.getAttribute('href');
        if (!href || href.charAt(0) === '#') continue;
        if (/^(?:[a-z][a-z0-9+.-]*:|\/\/)/i.test(href)) continue;
        if (href.charAt(0) === '/') continue;
        var path = href.split('#')[0].split('?')[0];
        if (!/\.html?$/i.test(path)) continue;
        var u;
        try { u = new URL(href, location.href); } catch (e) { continue; }
        if (u.protocol !== 'file:') continue;
        if (u.searchParams.has(URL_KEY)) continue;
        u.searchParams.set(URL_KEY, t);
        a.setAttribute('href', u.href);
      }
    }
    decorate();
    document.addEventListener('DOMContentLoaded', decorate);
    window.addEventListener('load', decorate);
    document.addEventListener('click', decorate, true);
  }

  /* ---------------- 启动 ---------------- */
  var stored = readStore(), fromUrl = urlToken();
  if (validToken(stored)) {
    cleanUrl();
    installLinks();
    return;
  }
  if (validToken(fromUrl)) {
    writeStore(fromUrl);
    cleanUrl();
    installLinks();
    return;
  }
  lock();
  showOverlay();
  /* 兜底：若脚本运行环境异常导致遮罩未出现，3 秒后恢复页面，避免白屏 */
  setTimeout(function () {
    if (overlay && !document.getElementById('wb-gate-overlay')) release();
  }, 3000);
})();
