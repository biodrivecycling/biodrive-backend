/**
 * BioDrive API client (auth + profile/powers).
 * Include: <script src="biodrive-api.js"></script>
 * Optional before load: window.BD_API_BASE = 'https://biodrive-backend.onrender.com';
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

  /** Merge server profile into localStorage (server wins on provided keys) */
  function applyProfileLocally(profile) {
    if (!profile || typeof profile !== 'object') return;
    try {
      var local = {};
      try { local = JSON.parse(localStorage.getItem('bd_profile') || '{}') || {}; } catch (e) { local = {}; }
      var merged = Object.assign({}, local, profile);
      localStorage.setItem('bd_profile', JSON.stringify(merged));
      if (merged.firstName) localStorage.setItem('bd_first_name', merged.firstName);
      if (merged.lastName) localStorage.setItem('bd_last_name', merged.lastName);
      if (merged.name) localStorage.setItem('bd_name', merged.name);
      if (merged.email) localStorage.setItem('bd_email', merged.email);
      if (merged.onboardingComplete) localStorage.setItem('bd_onboarding_complete', 'true');
    } catch (e) {}
  }

  function applyPowersLocally(powers) {
    if (!powers || typeof powers !== 'object') return;
    try {
      var local = {};
      try { local = JSON.parse(localStorage.getItem('bd_powers') || '{}') || {}; } catch (e) { local = {}; }
      var merged = Object.assign({}, local, powers);
      localStorage.setItem('bd_powers', JSON.stringify(merged));
    } catch (e) {}
  }

  function applyServerBundle(data) {
    if (!data) return;
    if (data.user) applyUserLocally(data.user);
    if (data.profile) applyProfileLocally(data.profile);
    if (data.powers) applyPowersLocally(data.powers);
  }

  function clearSessionLocally() {
    setToken(null);
    try { localStorage.removeItem('bd_pending_verification'); } catch (e) {}
  }

  var api = {
    base: BASE,
    getToken: getToken,
    setToken: setToken,
    applyUserLocally: applyUserLocally,
    applyProfileLocally: applyProfileLocally,
    applyPowersLocally: applyPowersLocally,
    applyServerBundle: applyServerBundle,
    clearSessionLocally: clearSessionLocally,

    health: function () { return request('GET', '/api/health'); },

    signup: function (payload) { return request('POST', '/api/auth/signup', payload); },

    login: function (email, password) {
      return request('POST', '/api/auth/login', { email: email, password: password }).then(function (res) {
        if (res.ok && res.data.token) {
          setToken(res.data.token);
          applyServerBundle(res.data);
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
      return request('GET', '/api/auth/me').then(function (res) {
        if (res.ok) applyServerBundle(res.data);
        return res;
      });
    },

    verifyEmail: function (token) {
      return request('POST', '/api/auth/verify', { token: token }).then(function (res) {
        if (res.ok && res.data.token) {
          setToken(res.data.token);
          applyServerBundle(res.data);
        }
        return res;
      });
    },

    resendVerification: function (email) {
      return request('POST', '/api/auth/resend-verification', { email: email });
    },

    getProfile: function () {
      return request('GET', '/api/profile').then(function (res) {
        if (res.ok && res.data.profile) applyProfileLocally(res.data.profile);
        return res;
      });
    },

    saveProfile: function (profile) {
      return request('PUT', '/api/profile', { profile: profile }).then(function (res) {
        if (res.ok && res.data.profile) applyProfileLocally(res.data.profile);
        return res;
      });
    },

    getPowers: function () {
      return request('GET', '/api/powers').then(function (res) {
        if (res.ok && res.data.powers) applyPowersLocally(res.data.powers);
        return res;
      });
    },

    savePowers: function (powers) {
      return request('PUT', '/api/powers', { powers: powers }).then(function (res) {
        if (res.ok && res.data.powers) applyPowersLocally(res.data.powers);
        return res;
      });
    },

    isAvailable: function () {
      return request('GET', '/api/health').then(function (res) {
        return !!(res.ok && res.data && res.data.ok);
      }).catch(function () { return false; });
    }
  };

  global.BioDriveAPI = api;
})(typeof window !== 'undefined' ? window : this);
