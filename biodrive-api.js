/**
 * BioDrive API client (auth first).
 * Include on pages: <script src="biodrive-api.js"></script>
 *
 * Config (optional, before this script):
 *   window.BD_API_BASE = 'http://127.0.0.1:8787';
 */
(function (global) {
  var BASE = (global.BD_API_BASE || 'http://127.0.0.1:8787').replace(/\/$/, '');
  var TOKEN_KEY = 'bd_session_token';

  function getToken() {
    try { return localStorage.getItem(TOKEN_KEY); } catch (e) { return null; }
  }
  function setToken(token) {
    try {
      if (token) localStorage.setItem(TOKEN_KEY, token);
      else localStorage.removeItem(TOKEN_KEY);
    } catch (e) {}
  }

  function request(method, path, body) {
    var headers = { 'Content-Type': 'application/json' };
    var token = getToken();
    if (token) headers['Authorization'] = 'Bearer ' + token;
    return fetch(BASE + path, {
      method: method,
      headers: headers,
      body: body ? JSON.stringify(body) : undefined
    }).then(function (res) {
      return res.json().catch(function () { return {}; }).then(function (data) {
        return { status: res.status, ok: res.ok, data: data };
      });
    });
  }

  /** Apply server user into existing localStorage keys the UI already reads */
  function applyUserLocally(user) {
    if (!user) return;
    try {
      if (user.email) localStorage.setItem('bd_email', user.email);
      if (user.firstName) localStorage.setItem('bd_first_name', user.firstName);
      if (user.lastName) localStorage.setItem('bd_last_name', user.lastName);
      var full = ((user.firstName || '') + ' ' + (user.lastName || '')).trim();
      if (full) localStorage.setItem('bd_name', full);
      var prof = {};
      try { prof = JSON.parse(localStorage.getItem('bd_profile') || '{}') || {}; } catch (e) { prof = {}; }
      if (user.firstName) prof.firstName = user.firstName;
      if (user.lastName) prof.lastName = user.lastName;
      if (full) prof.name = full;
      if (user.email) prof.email = user.email;
      if (user.id) prof.userId = user.id;
      localStorage.setItem('bd_profile', JSON.stringify(prof));
    } catch (e) {}
  }

  function clearSessionLocally() {
    setToken(null);
    // Keep marketing UX but drop auth-ish keys; full wipe matches current logout
    try {
      var keys = [];
      for (var i = 0; i < localStorage.length; i++) {
        var k = localStorage.key(i);
        if (k && k.indexOf('bd_') === 0) keys.push(k);
      }
      keys.forEach(function (k) { localStorage.removeItem(k); });
    } catch (e) {}
  }

  var api = {
    base: BASE,
    getToken: getToken,
    setToken: setToken,
    applyUserLocally: applyUserLocally,
    clearSessionLocally: clearSessionLocally,

    health: function () {
      return request('GET', '/api/health');
    },

    signup: function (payload) {
      return request('POST', '/api/auth/signup', payload);
    },

    login: function (email, password) {
      return request('POST', '/api/auth/login', { email: email, password: password }).then(function (res) {
        if (res.ok && res.data.token) {
          setToken(res.data.token);
          applyUserLocally(res.data.user);
        }
        return res;
      });
    },

    logout: function () {
      return request('POST', '/api/auth/logout').then(function (res) {
        clearSessionLocally();
        return res;
      }).catch(function () {
        clearSessionLocally();
        return { ok: false };
      });
    },

    me: function () {
      return request('GET', '/api/auth/me');
    },

    verifyEmail: function (token) {
      return request('POST', '/api/auth/verify', { token: token }).then(function (res) {
        if (res.ok && res.data.token) {
          setToken(res.data.token);
          applyUserLocally(res.data.user);
        }
        return res;
      });
    },

    resendVerification: function (email) {
      return request('POST', '/api/auth/resend-verification', { email: email });
    },

    /** true if API responds to /api/health */
    isAvailable: function () {
      return request('GET', '/api/health').then(function (res) {
        return !!(res.ok && res.data && res.data.ok);
      }).catch(function () { return false; });
    }
  };

  global.BioDriveAPI = api;
})(typeof window !== 'undefined' ? window : this);
