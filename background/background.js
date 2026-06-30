/**
 * NERD IP info - Background Service Worker (Manifest V3)
 *
 * Handles runtime messages, performs authenticated NERD API lookups,
 * and provides a context-menu action to search selected text.
 */

/* global chrome */

const DEFAULT_API_BASE_URL = 'https://nerd.cesnet.cz/nerd/api/v1';
const REQUEST_TIMEOUT_MS = 10000;
const DEFAULT_MAX_RETRIES = 3;
const DEFAULT_RETRY_BASE_DELAY_MS = 1000;
const BULK_SCAN_MAX_IPS = 1000;
const MAP_TTL_MS = 24 * 60 * 60 * 1000; // refresh once per day

// ------------------------------------------------------------------
// Context menu
// ------------------------------------------------------------------

const CONTEXT_MENU_ID = 'searchSelectedText';
const CONTEXT_MENU_TITLE = 'Search using NERD';

/**
 * Registers the context menu item once per extension install/update.
 */
function registerContextMenu() {
  chrome.contextMenus.create({
    id: CONTEXT_MENU_ID,
    title: CONTEXT_MENU_TITLE,
    contexts: ['selection']
  });
}

chrome.runtime.onInstalled.addListener(registerContextMenu);

chrome.contextMenus.onClicked.addListener((info) => {
  if (info.menuItemId === CONTEXT_MENU_ID && info.selectionText) {
    storePendingIpAndOpenPopup(info.selectionText.trim());
  }
});

// ------------------------------------------------------------------
// Runtime message handlers
// ------------------------------------------------------------------

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.action === 'openPopup') {
    openPopup(message.ip)
      .then(() => sendResponse({ ok: true }))
      .catch((error) => {
        sendResponse({ ok: false, error: error && error.message ? error.message : String(error) });
      });
    return true; // keep channel open for async response
  }

  if (message.action === 'lookupIp' && message.ip) {
    lookupIp(message.ip)
      .then((result) => sendResponse(result))
      .catch((error) => sendResponse({ ok: false, error: error.message }));
    return true; // keep the message channel open for the async response
  }

  if (message.action === 'lookupRepBulk' && Array.isArray(message.ips)) {
    lookupRepBulk(message.ips)
      .then((result) => sendResponse(result))
      .catch((error) => sendResponse({ ok: false, error: error.message }));
    return true;
  }

  if (message.action === 'ensureTags') {
    ensureFreshTagMap(Boolean(message.force))
      .then((tagMap) => sendResponse({ ok: true, tagMap }))
      .catch((error) => sendResponse({ ok: false, error: error.message }));
    return true;
  }

  if (message.action === 'ensureBlacklists') {
    ensureFreshBlacklistMap(Boolean(message.force))
      .then((blacklistMap) => sendResponse({ ok: true, blacklistMap }))
      .catch((error) => sendResponse({ ok: false, error: error.message }));
    return true;
  }

  return false;
});

// ------------------------------------------------------------------
// Tag / blacklist map refresh hooks
// ------------------------------------------------------------------

chrome.runtime.onInstalled.addListener(() => {
  refreshMaps().catch(() => {});
});

chrome.runtime.onStartup && chrome.runtime.onStartup.addListener(() => {
  refreshMaps().catch(() => {});
});

/**
 * Refreshes both tag and blacklist maps in parallel.
 * @returns {Promise<void>}
 */
function refreshMaps() {
  return Promise.all([
    ensureFreshTagMap().catch(() => {}),
    ensureFreshBlacklistMap().catch(() => {})
  ]).then(() => {});
}

// ------------------------------------------------------------------
// Popup helpers
// ------------------------------------------------------------------

/**
 * Opens the extension popup if the runtime API allows it.
 * chrome.action.openPopup() returns a Promise in Manifest V3; this helper
 * awaits it so rejections are caught instead of becoming uncaught promise
 * errors.
 *
 * On Firefox, chrome.action.openPopup() is unavailable, so the popup UI is
 * opened in a small detached window instead.
 * @param {string} [ip]
 */
async function openPopup(ip) {
  // Chrome path
  if (typeof chrome !== 'undefined' && chrome.action && chrome.action.openPopup) {
    try {
      await chrome.action.openPopup();
      return;
    } catch (_) {}
  }

  // Firefox fallback: open the popup UI in a small detached window
  const url = new URL(chrome.runtime.getURL('popup/popup.html'));
  if (ip) {
    url.searchParams.set('ip', ip);
  }

  try {
    await chrome.windows.create({
      url: url.toString(),
      type: 'popup',
      width: 420,
      height: 640
    });
  } catch (_) {
    // Last-resort fallback
    chrome.tabs.create({ url: url.toString() });
  }
}

/**
 * Saves an IP as pending and tries to open the popup so the user sees
 * the result immediately.
 * @param {string} ip
 */
function storePendingIpAndOpenPopup(ip) {
  if (!ip) return;
  chrome.storage.local.set({ pendingIp: ip }, () => {
    openPopup(ip).catch(() => {});
  });
}

// ------------------------------------------------------------------
// Settings helpers
// ------------------------------------------------------------------

/**
 * Reads the API token from chrome.storage.local.
 * @returns {Promise<string>}
 */
function getApiToken() {
  return new Promise((resolve) => {
    chrome.storage.local.get({ apiToken: '' }, (storage) => {
      resolve((storage.apiToken || '').trim());
    });
  });
}

// ------------------------------------------------------------------
// API lookup
// ------------------------------------------------------------------

/**
 * Looks up an IP address against the NERD API.
 * @param {string} ip
 * @returns {Promise<{ok: boolean, data?: object, error?: string}>}
 */
async function lookupIp(ip) {
  const apiToken = await getApiToken();
  if (!apiToken) {
    return { ok: false, error: 'Missing API key' };
  }

  const url = `${DEFAULT_API_BASE_URL}/ip/${encodeURIComponent(ip)}`;

  const result = await fetchWithRetry(url, apiToken);
  if (!result.ok) return result;

  try {
    const data = typeof result.data === 'object' ? result.data : JSON.parse(result.data);
    return { ok: true, data };
  } catch (err) {
    return { ok: false, error: 'Invalid JSON response' };
  }
}

/**
 * Looks up reputation scores for multiple IP addresses in a single request.
 * Endpoint: {DEFAULT_API_BASE_URL}/ip/bulk
 * The IP list is capped to BULK_SCAN_MAX_IPS to keep the request/response
 * bounded. The caller is responsible for prioritizing which IPs to scan.
 * @param {string[]} ips
 * @returns {Promise<{ok: boolean, scores?: Record<string, number|null>, error?: string}>}
 */
async function lookupRepBulk(ips) {
  const apiToken = await getApiToken();
  if (!apiToken) {
    return { ok: false, error: 'Missing API key' };
  }

  let uniqueIps = [...new Set(ips.map((ip) => String(ip).trim()).filter(Boolean))];
  if (uniqueIps.length === 0) {
    return { ok: true, scores: {} };
  }
  if (uniqueIps.length > BULK_SCAN_MAX_IPS) {
    uniqueIps = uniqueIps.slice(0, BULK_SCAN_MAX_IPS);
  }

  const url = `${DEFAULT_API_BASE_URL}/ip/bulk`;
  const body = uniqueIps.join(',');

  const result = await fetchWithRetry(url, apiToken, {
    method: 'POST',
    body,
    contentType: 'text/plain'
  });
  if (!result.ok) return result;

  const scores = parseBulkScores(result.data, uniqueIps);
  if (!scores) {
    return { ok: false, error: 'Invalid bulk reputation response' };
  }

  return { ok: true, scores };
}

// ------------------------------------------------------------------
// Generic map fetching and caching (tags / blacklists)
// ------------------------------------------------------------------

/**
 * Generic cache reader for a map stored with its timestamp.
 * @param {string} mapKey
 * @param {string} tsKey
 * @returns {Promise<{map: Record<string,string>|null, ts: number}>}
 */
function getCachedMap(mapKey, tsKey) {
  return new Promise((resolve) => {
    chrome.storage.local.get({ [mapKey]: null, [tsKey]: 0 }, (storage) => {
      resolve({
        map: storage[mapKey] || null,
        ts: storage[tsKey] || 0
      });
    });
  });
}

/**
 * Generic storage writer for a map and its timestamp.
 * @param {string} mapKey
 * @param {string} tsKey
 * @param {Record<string,string>} map
 * @param {number} ts
 * @returns {Promise<void>}
 */
function storeMap(mapKey, tsKey, map, ts) {
  return new Promise((resolve, reject) => {
    chrome.storage.local.set({ [mapKey]: map, [tsKey]: ts }, () => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
      } else {
        resolve();
      }
    });
  });
}

/**
 * Normalizes a tag/blacklist info response into an id -> name map.
 * @param {any} data
 * @returns {Record<string,string>}
 */
function normalizeInfoMap(data) {
  const map = {};

  function addEntry(id, name) {
    if (id === null || id === undefined) return;
    if (typeof name !== 'string' || name.trim() === '') return;
    map[String(id).trim()] = name.trim();
  }

  if (data && typeof data === 'object' && !Array.isArray(data)) {
    for (const id of Object.keys(data)) {
      const value = data[id];
      if (typeof value === 'string') {
        addEntry(id, value);
      } else if (value && typeof value === 'object' && typeof value.name === 'string') {
        addEntry(id, value.name);
      }
    }
  } else if (Array.isArray(data)) {
    for (const item of data) {
      if (item && typeof item === 'object') {
        const id = item.id || item.key || item.tag || item.blacklist || item._id;
        const name = item.name || item.label || item.value || item.full_name;
        addEntry(id, name);
      }
    }
  }

  return map;
}

/**
 * Returns the cached tag map from storage if it is still fresh.
 * @returns {Promise<{tagMap: Record<string,string>|null, tagMapTs: number}>}
 */
function getCachedTagMap() {
  return getCachedMap('tagMap', 'tagMapTs').then(({ map, ts }) => ({
    tagMap: map,
    tagMapTs: ts
  }));
}

/**
 * Fetches the tag info endpoint and normalizes the response into an id -> name map.
 * Requires a valid API token.
 * @returns {Promise<Record<string,string>>}
 */
async function fetchTags() {
  const apiToken = await getApiToken();
  if (!apiToken) {
    throw new Error('Missing API key');
  }

  const url = `${DEFAULT_API_BASE_URL}/tag_info`;
  const result = await fetchWithRetry(url, apiToken);
  if (!result.ok) {
    throw new Error(result.error || 'Tag info request failed');
  }

  return normalizeInfoMap(result.data);
}

/**
 * Fetches and stores the tag map. If the fetch fails and a cached map exists,
 * the cached map is returned so the popup can keep working.
 * @returns {Promise<Record<string,string>>}
 */
async function ensureFreshTagMap(force = false) {
  const { tagMap, tagMapTs } = await getCachedTagMap();
  const now = Date.now();
  const isEmpty = !tagMap || Object.keys(tagMap).length === 0;
  const isFresh = !isEmpty && tagMapTs && now - tagMapTs < MAP_TTL_MS;

  if (!force && isFresh) {
    return tagMap;
  }

  try {
    const fresh = await fetchTags();
    await storeMap('tagMap', 'tagMapTs', fresh, now);
    return fresh;
  } catch (err) {
    if (tagMap) {
      return tagMap;
    }
    throw err;
  }
}

/**
 * Returns the cached blacklist map from storage if it is still fresh.
 * @returns {Promise<{blacklistMap: Record<string,string>|null, blacklistMapTs: number}>}
 */
function getCachedBlacklistMap() {
  return getCachedMap('blacklistMap', 'blacklistMapTs').then(({ map, ts }) => ({
    blacklistMap: map,
    blacklistMapTs: ts
  }));
}

/**
 * Fetches the blacklist info endpoint and normalizes the response into an id -> name map.
 * Requires a valid API token.
 * @returns {Promise<Record<string,string>>}
 */
async function fetchBlacklists() {
  const apiToken = await getApiToken();
  if (!apiToken) {
    throw new Error('Missing API key');
  }

  const url = `${DEFAULT_API_BASE_URL}/blacklist_info`;
  const result = await fetchWithRetry(url, apiToken);
  if (!result.ok) {
    throw new Error(result.error || 'Blacklist info request failed');
  }

  return normalizeInfoMap(result.data);
}

/**
 * Fetches and stores the blacklist map. If the fetch fails and a cached map exists,
 * the cached map is returned so the popup can keep working.
 * @returns {Promise<Record<string,string>>}
 */
async function ensureFreshBlacklistMap(force = false) {
  const { blacklistMap, blacklistMapTs } = await getCachedBlacklistMap();
  const now = Date.now();
  const isEmpty = !blacklistMap || Object.keys(blacklistMap).length === 0;
  const isFresh = !isEmpty && blacklistMapTs && now - blacklistMapTs < MAP_TTL_MS;

  if (!force && isFresh) {
    return blacklistMap;
  }

  try {
    const fresh = await fetchBlacklists();
    await storeMap('blacklistMap', 'blacklistMapTs', fresh, now);
    return fresh;
  } catch (err) {
    if (blacklistMap) {
      return blacklistMap;
    }
    throw err;
  }
}

/**
 * Parses the bulk endpoint response into a map of IP -> score.
 * The API returns ASCII-coded decimal numbers separated by commas,
 * one per IP, in the same order as the request.
 * @param {string} text
 * @param {string[]} ips
 * @returns {Record<string, number|null>|null}
 */
function parseBulkScores(text, ips) {
  if (typeof text !== 'string') return null;
  const trimmed = text.trim();
  if (trimmed === '') return null;

  // The API returns one score per line when no commas are present,
  // or comma-separated values when requested as text/plain.
  let parts = trimmed.includes(',') ? trimmed.split(',') : trimmed.split(/\s+/);
  parts = parts.map((p) => p.trim()).filter((p) => p !== '');
  if (parts.length !== ips.length) return null;

  const scores = {};
  for (let i = 0; i < ips.length; i++) {
    const part = parts[i];
    if (part === '') {
      scores[ips[i]] = null;
      continue;
    }
    const parsed = Number(part);
    if (!Number.isFinite(parsed)) {
      scores[ips[i]] = null;
    } else {
      scores[ips[i]] = parsed;
    }
  }
  return scores;
}

/**
 * Performs a GET request with timeout, retries, and graceful handling of
 * network errors and rate limiting.
 * @param {string} url
 * @param {string} apiToken
 * @param {object} [options]
 * @returns {Promise<{ok: boolean, data?: any, error?: string}>}
 */
async function fetchWithRetry(url, apiToken, options = {}) {
  const maxRetries = options.maxRetries ?? DEFAULT_MAX_RETRIES;
  const baseDelay = options.baseDelay ?? DEFAULT_RETRY_BASE_DELAY_MS;
  const timeout = options.timeout ?? REQUEST_TIMEOUT_MS;
  const method = options.method || 'GET';
  const body = options.body || undefined;
  const contentType = options.contentType || 'application/json';
  let lastError = null;

  const headers = {
    Authorization: apiToken,
    Accept: 'application/json'
  };
  if (method === 'POST' && body !== undefined) {
    headers['Content-Type'] = contentType;
  }

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    try {
      const resp = await fetch(url, {
        method,
        headers,
        body,
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (resp.status === 429) {
        const retryAfter = parseInt(resp.headers.get('Retry-After') || '0', 10);
        const delay = retryAfter > 0 ? retryAfter * 1000 : baseDelay * Math.pow(2, attempt);
        lastError = 'Rate limited (HTTP 429)';
        if (attempt < maxRetries) {
          await sleep(delay);
          continue;
        }
        return { ok: false, error: lastError };
      }

      if (resp.status >= 500 && resp.status < 600) {
        lastError = `Server error (HTTP ${resp.status})`;
        if (attempt < maxRetries) {
          await sleep(baseDelay * Math.pow(2, attempt));
          continue;
        }
        return { ok: false, error: lastError };
      }

      if (resp.status === 404) {
        return { ok: false, error: '404' };
      }
      if (resp.status === 400) {
        return { ok: false, error: '400' };
      }
      if (!resp.ok) {
        return { ok: false, error: `HTTP ${resp.status}` };
      }

      const text = await resp.text();
      let data = text;
      try {
        data = JSON.parse(text);
      } catch (_) {
        // Keep the raw text; callers can parse it themselves.
      }
      return { ok: true, data };
    } catch (err) {
      clearTimeout(timeoutId);
      lastError = err.name === 'AbortError' ? 'Request timed out' : err.message;
      if (attempt < maxRetries) {
        await sleep(baseDelay * Math.pow(2, attempt));
      }
    }
  }

  return { ok: false, error: lastError };
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
