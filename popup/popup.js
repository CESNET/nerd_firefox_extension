/**
 * NERD IP info - Popup Script
 *
 * Drives the extension popup UI: manual IP lookup, result rendering,
 * recent history, raw JSON clipboard copy, and settings link.
 */

/* global chrome */

document.addEventListener('DOMContentLoaded', () => {
  // ------------------------------------------------------------------
  // Initial IP from URL query parameter (used by Firefox fallback window)
  // ------------------------------------------------------------------
  const urlParams = new URLSearchParams(window.location.search);
  const urlIp = urlParams.get('ip');

  // ------------------------------------------------------------------
  // DOM references
  // ------------------------------------------------------------------
  const ipInput       = document.getElementById('ipInput');
  const lookupBtn     = document.getElementById('lookupBtn');
  const pageScanBtn   = document.getElementById('pageScanBtn');
  const pageScanSpinner = document.getElementById('pageScanSpinner');
  const pageScanStatus = document.getElementById('pageScanStatus');
  const resultsEl     = document.getElementById('results');
  const statusEl      = document.getElementById('status');
  const toggleSwitch  = document.getElementById('toggleSwitch');
  const toggleStatus  = document.getElementById('toggleStatus');
  const settingsLink  = document.getElementById('settingsLink');
  const resultCard    = document.getElementById('resultCard');
  const ipAddressEl   = document.getElementById('ipAddress');
  const hostnameEl    = document.getElementById('hostname');
  const trafficLight  = document.getElementById('trafficLight');
  const verdictEl     = document.getElementById('verdict');
  const threatCatEl   = document.getElementById('threatCategory');
  const scoreEl       = document.getElementById('score');
  const tagsEl        = document.getElementById('tags');
  const detailsEl     = document.getElementById('details');
  const nerdLink      = document.getElementById('nerdLink');
  const copyRawJsonBtn = document.getElementById('copyRawJsonBtn');
  const addToBlocklistBtn = document.getElementById('addToBlocklistBtn');
  const addToAllowlistBtn = document.getElementById('addToAllowlistBtn');
  const siteListActionStatus = document.getElementById('siteListActionStatus');

  // Holds the raw JSON string for the current lookup (used by Copy raw JSON)
  let currentRawJson = '';

  // Tag / blacklist id -> name maps shared from the background service worker.
  let tagMap = {};
  let blacklistMap = {};

  // ------------------------------------------------------------------
  // Boot: restore saved state
  // ------------------------------------------------------------------
  chrome.storage.local.get(
    { detectionEnabled: true, recent: [], pendingIp: null, tagMap: {}, blacklistMap: {} },
    (data) => {
      tagMap = data.tagMap || {};
      blacklistMap = data.blacklistMap || {};
      setToggle(data.detectionEnabled);
      renderRecent(data.recent || []);

      const initialIp = urlIp || data.pendingIp;
      if (initialIp) {
        ipInput.value = initialIp;
        performLookup(initialIp);
        if (data.pendingIp) {
          // Leave pendingIp in storage for a moment so that any other code
          // reacting to the same click can still observe it. It is cleared
          // after the lookup starts.
          setTimeout(() => chrome.storage.local.remove('pendingIp'), 50);
        }
      }
    }
  );

  ensureFreshTagMap();
  ensureFreshBlacklistMap();

  // ------------------------------------------------------------------
  // Live updates while popup is open
  // ------------------------------------------------------------------
  chrome.storage.onChanged.addListener((changes) => {
    if (changes.pendingIp && changes.pendingIp.newValue) {
      const ip = changes.pendingIp.newValue;
      ipInput.value = ip;
      performLookup(ip);
      // Defer clearing pendingIp slightly so background code that is still
      // reacting to the same click can see the value.
      setTimeout(() => chrome.storage.local.remove('pendingIp'), 50);
    }
    if (changes.tagMap && changes.tagMap.newValue) {
      tagMap = changes.tagMap.newValue;
      refreshCurrentResultCard();
    }
    if (changes.blacklistMap && changes.blacklistMap.newValue) {
      blacklistMap = changes.blacklistMap.newValue;
      refreshCurrentResultCard();
    }
  });

  /**
   * Re-renders the currently visible result card when maps change.
   */
  function refreshCurrentResultCard() {
    if (!resultCard.classList.contains('hidden') && ipAddressEl.textContent) {
      const ip = ipAddressEl.textContent;
      chrome.storage.local.get({ recent: [] }, (data) => {
        const entry = (data.recent || []).find((r) => r.ip === ip && r.resp && r.resp.ok);
        if (entry) {
          showResultCard(ip, entry.resp.data);
        }
      });
    }
  }

  // ------------------------------------------------------------------
  // Event: enable / disable page detection
  // ------------------------------------------------------------------
  toggleSwitch.addEventListener('change', (e) => {
    const enabled = e.target.checked;
    chrome.storage.local.set({ detectionEnabled: enabled }, () => {
      setToggle(enabled);
      showStatus(enabled ? 'Detection enabled' : 'Detection disabled', 2500);
    });
  });

  // ------------------------------------------------------------------
  // Event: open the browser's extension options page
  // ------------------------------------------------------------------
  settingsLink.addEventListener('click', (e) => {
    e.preventDefault();
    openOptionsPage();
  });

  // ------------------------------------------------------------------
  // Event: add current site to blocklist / allowlist
  // ------------------------------------------------------------------
  addToBlocklistBtn.addEventListener('click', () => addCurrentSiteToList('block'));
  addToAllowlistBtn.addEventListener('click', () => addCurrentSiteToList('allow'));

  // ------------------------------------------------------------------
  // Event: manual lookup
  // ------------------------------------------------------------------
  lookupBtn.addEventListener('click', () => performLookup(ipInput.value.trim()));
  ipInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') performLookup(ipInput.value.trim());
  });

  // ------------------------------------------------------------------
  // Event: copy raw JSON to clipboard
  // ------------------------------------------------------------------
  copyRawJsonBtn.addEventListener('click', () => copyToClipboard(currentRawJson, copyRawJsonBtn));

  // ------------------------------------------------------------------
  // Event: scan visible IPs on the current page
  // ------------------------------------------------------------------
  pageScanBtn.addEventListener('click', () => triggerPageScan());

  // ==================================================================
  // Page scan logic
  // ==================================================================

  let pageScanInProgress = false;

  async function triggerPageScan() {
    if (pageScanInProgress) return;
    pageScanInProgress = true;
    setPageScanLoading(true, 'Scanning page…');

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab || !tab.id) {
        setPageScanLoading(false, 'No active tab.');
        return;
      }

      // The content script may not have run on this URL (e.g. chrome:// pages).
      // sendMessage will fail with "Could not establish connection" if the tab
      // is not accessible or the content script is not present.
      const scanResult = await chrome.tabs.sendMessage(tab.id, { action: 'scanAllVisibleIPs' });
      const statusText = scanResult && typeof scanResult.status === 'string'
        ? scanResult.status
        : 'Scan complete.';

      setPageScanLoading(false, statusText);
    } catch (err) {
      setPageScanLoading(false, 'Scan failed: ' + (err && err.message ? err.message : String(err)));
    } finally {
      pageScanInProgress = false;
      setTimeout(() => setPageScanLoading(false, ''), 4000);
    }
  }

  function setPageScanLoading(loading, text) {
    pageScanBtn.disabled = loading;
    pageScanSpinner.style.display = loading ? 'inline-block' : 'none';
    pageScanStatus.textContent = text || '';
  }

  // ==================================================================
  // Core lookup logic
  // ==================================================================

  function performLookup(ip) {
    if (!ip) return;

    statusEl.textContent = 'Looking up…';
    resultCard.classList.add('hidden');

    chrome.runtime.sendMessage({ action: 'lookupIp', ip }, handleLookupResponse(ip));
  }

  /**
   * Builds a response handler for a specific IP lookup.
   * @param {string} ip
   * @returns {Function}
   */
  function handleLookupResponse(ip) {
    return (resp) => {
      statusEl.textContent = '';

      if (chrome.runtime.lastError) {
        statusEl.textContent = 'Error: ' + chrome.runtime.lastError.message;
        return;
      }
      if (!resp) {
        statusEl.textContent = 'No response from service worker.';
        return;
      }
      if (!resp.ok) {
        handleLookupError(resp.error);
        return;
      }

      showResultCard(ip, resp.data);
      addRecent(ip, resp);
    };
  }

  /**
   * Displays server / client errors in the status area.
   * @param {string} error
   */
  function handleLookupError(error) {
    if (error === '401' || error === '403' || error === 'Missing API key') {
      buildMissingApiKeyStatus();
    } else if (error === '404') {
      showResultCard(ipInput.value.trim(), null);
    } else if (error === 'Request timed out') {
      statusEl.textContent = 'Error: Request timed out. Please try again.';
    } else {
      statusEl.textContent = 'Error: ' + error;
    }
  }

  // ==================================================================
  // Result card rendering
  // ==================================================================

  function showResultCard(ip, data) {
    resultCard.classList.remove('hidden');

    const { verdict, color, scoreText } = getVerdictAndColor(data);
    trafficLight.className = 'traffic-light ' + color;

    ipAddressEl.textContent = ip;
    setText(hostnameEl, getHostname(data));
    verdictEl.textContent = verdict;
    setText(threatCatEl, getThreatCategories(data).map(resolveTagName).join(', '));
    scoreEl.textContent = 'Score: ' + scoreText;

    renderTags(getTags(data));
    renderDetails(data);

    nerdLink.href = 'https://nerd.cesnet.cz/nerd/ip/' + encodeURIComponent(ip);
    nerdLink.textContent = 'Open in NERD';

    currentRawJson = data ? JSON.stringify(data, null, 2) : '';
  }

  /**
   * Resolves a blacklist ID to its human-readable name using the cached blacklist map.
   * Falls back to the raw value when no mapping exists.
   * @param {string} blacklist
   * @returns {string}
   */
  function resolveBlacklistName(blacklist) {
    const raw = String(blacklist).trim();
    if (blacklistMap && typeof blacklistMap[raw] === 'string') {
      return blacklistMap[raw];
    }
    return raw;
  }

  /**
   * Asks the background service worker to refresh the tag map if it is stale.
   * Updates the current result card if one is visible.
   */
  async function ensureFreshTagMap(force = false) {
    try {
      const response = await new Promise((resolve) => {
        chrome.runtime.sendMessage({ action: 'ensureTags', force }, resolve);
      });
      if (response && response.ok && response.tagMap && typeof response.tagMap === 'object') {
        tagMap = response.tagMap;
        refreshCurrentResultCard();
      }
    } catch (_) {}
  }

  /**
   * Asks the background service worker to refresh the blacklist map if it is stale.
   * Updates the current result card if one is visible.
   */
  async function ensureFreshBlacklistMap(force = false) {
    try {
      const response = await new Promise((resolve) => {
        chrome.runtime.sendMessage({ action: 'ensureBlacklists', force }, resolve);
      });
      if (response && response.ok && response.blacklistMap && typeof response.blacklistMap === 'object') {
        blacklistMap = response.blacklistMap;
        refreshCurrentResultCard();
      }
    } catch (_) {}
  }

  /**
   * Resolves a tag ID to its human-readable name using the cached tag map.
   * Falls back to the raw value when no mapping exists.
   * @param {string} tag
   * @returns {string}
   */
  function resolveTagName(tag) {
    const raw = String(tag).trim();
    if (tagMap && typeof tagMap[raw] === 'string') {
      return tagMap[raw];
    }
    return raw;
  }

  function renderTags(tags) {
    clearChildren(tagsEl);

    if (!tags || !tags.length) return;

    const label = document.createElement('span');
    label.className = 'tags-label';
    label.textContent = 'tags:';
    tagsEl.appendChild(label);

    for (const tag of tags) {
      const span = document.createElement('span');
      span.className = 'tag';
      span.textContent = resolveTagName(tag);
      span.title = String(tag);
      tagsEl.appendChild(span);
    }
  }

  function renderDetails(data) {
    clearChildren(detailsEl);
    if (data) {
      detailsEl.appendChild(renderObjectDetails(data));
    } else {
      const p = document.createElement('p');
      p.style.color = '#888';
      p.textContent = 'Click Open in NERD to get more information.';
      detailsEl.appendChild(p);
    }
  }

  function getVerdictAndColor(data) {
    if (!data) {
      return { verdict: 'No data - likely clean', color: 'green', scoreText: 'N/A' };
    }
    if (typeof data.rep !== 'number') {
      return { verdict: 'Unknown', color: 'gray', scoreText: 'N/A' };
    }
    const rep = data.rep;
    if (rep > 0.5) return { verdict: 'Malicious',  color: 'red',    scoreText: rep.toFixed(4) };
    if (rep > 0.2) return { verdict: 'Suspicious', color: 'orange', scoreText: rep.toFixed(4) };
    return { verdict: 'Likely clean', color: 'green', scoreText: rep.toFixed(4) };
  }

  // ------------------------------------------------------------------
  // Dynamic object rendering (returns DocumentFragment)
  // ------------------------------------------------------------------

  function renderObjectDetails(obj, parentKey) {
    const skipKeys = ['_id', 'rep', 'tags', 'categories', 'threat_category', 'hostname', 'host', 'name', 'fmp', 'fmp_general', 'fmp.general', 'ip'];
    const networkKeys = ['asn', 'bgppref', 'ipblock', 'country', 'geo'];
    const blacklistKeys = ['bl', 'blacklist', 'blacklists'];

    const networkFragment = document.createDocumentFragment();
    const blacklistFragment = document.createDocumentFragment();
    const restFragment = document.createDocumentFragment();

    function renderGeo(value) {
      if (value && typeof value === 'object') {
        const countryCode = value.ctry || value.country;
        if (countryCode) {
          networkFragment.appendChild(renderPrimitivePair('country', countryCode, ''));
        }
      }
    }

    for (const key of Object.keys(obj)) {
      const value = obj[key];
      if (value === null || value === undefined) continue;
      if (skipKeys.includes(key)) continue;

      const displayKey = parentKey ? parentKey + '.' + key : key;

      if (key === 'geo' && !parentKey) {
        renderGeo(value);
        continue;
      }

      if (networkKeys.includes(key)) {
        if (hasValue(value)) {
          networkFragment.appendChild(renderPrimitivePair(key, value, parentKey));
        }
        continue;
      }

      if (blacklistKeys.includes(key)) {
        const blValue = Array.isArray(value) && !value.length
          ? 'No blacklist entries'
          : value;
        blacklistFragment.appendChild(renderBlacklistPair(key, blValue, parentKey));
        continue;
      }

      if (typeof value === 'object' && !Array.isArray(value)) {
        for (const bk of blacklistKeys) {
          if (value[bk] !== undefined) {
            blacklistFragment.appendChild(renderBlacklistPair(bk, value[bk], displayKey));
          }
        }
        restFragment.appendChild(renderObjectDetails(value, displayKey));
      } else if (Array.isArray(value)) {
        if (!value.length) continue;
        restFragment.appendChild(renderPrimitivePair(key, value, parentKey));
      } else if (typeof value === 'number' || typeof value === 'boolean') {
        restFragment.appendChild(renderPrimitivePair(key, value, parentKey));
      } else if (typeof value === 'string') {
        restFragment.appendChild(renderStringPair(displayKey, value));
      }
    }

    const combined = document.createDocumentFragment();
    combined.appendChild(networkFragment);
    combined.appendChild(blacklistFragment);
    combined.appendChild(restFragment);
    return combined;
  }

  function renderPrimitivePair(key, value, prefix) {
    const displayKey = prefix ? prefix + '.' + key : key;
    const p = document.createElement('p');
    const strong = document.createElement('strong');
    strong.textContent = capitalize(displayKey) + ':';
    p.appendChild(strong);

    if (Array.isArray(value)) {
      p.appendChild(document.createTextNode(' ' + value.map(formatArrayItem).join(', ')));
    } else {
      p.appendChild(document.createTextNode(' ' + String(value)));
    }
    return p;
  }

  /**
   * Renders a blacklist key/value pair, resolving blacklist IDs to names.
   * Entries are displayed as compact clickable pill chips linking to the
   * NERD feed page. The raw ID is available via the title attribute.
   */
  function renderBlacklistPair(key, value, prefix) {
    const displayKey = prefix ? prefix + '.' + key : key;
    const p = document.createElement('p');
    p.className = 'blacklist-row';

    const label = document.createElement('strong');
    const labelText = displayKey === 'bl' ? 'blacklists' : displayKey;
    label.textContent = capitalize(labelText) + ':';
    p.appendChild(label);

    const list = document.createElement('span');
    list.className = 'blacklist-list';

    if (!Array.isArray(value)) {
      value = [value];
    }

    for (const raw of value) {
      if (raw === null || raw === undefined) continue;
      const rawId = String(raw);
      const item = document.createElement('a');
      item.className = 'blacklist-item';
      item.href = 'https://nerd.cesnet.cz/nerd/feed/' + encodeURIComponent(rawId);
      item.title = rawId;
      item.textContent = resolveBlacklistName(raw);
      if (rawId.toLowerCase() !== 'no blacklist entries') {
        item.target = '_blank';
        item.rel = 'noopener noreferrer';
        item.addEventListener('click', (e) => {
          e.stopPropagation();
        });
      } else {
        item.classList.add('blacklist-item-empty');
        item.addEventListener('click', (e) => {
          e.preventDefault();
          e.stopPropagation();
        });
      }
      list.appendChild(item);
    }

    p.appendChild(list);
    return p;
  }

  function renderStringPair(displayKey, value) {
    const p = document.createElement('p');
    const strong = document.createElement('strong');
    strong.textContent = capitalize(displayKey) + ':';
    p.appendChild(strong);

    if (/^\d{4}-\d{2}-\d{2}T/.test(value)) {
      try {
        p.appendChild(document.createTextNode(' ' + new Date(value).toLocaleString()));
      } catch (_) {
        p.appendChild(document.createTextNode(' ' + value));
      }
    } else {
      p.appendChild(document.createTextNode(' ' + value));
    }
    return p;
  }

  function hasValue(value) {
    if (value === null || value === undefined) return false;
    if (typeof value === 'string' && !value.trim()) return false;
    if (Array.isArray(value) && !value.length) return false;
    return true;
  }

  function formatArrayItem(v) {
    if (v === null || v === undefined) return '';
    if (typeof v === 'object' && !Array.isArray(v)) {
      return resolveTagName(v.category || v.name || v.label || v.type || v.n || JSON.stringify(v));
    }
    return resolveTagName(v);
  }

  /** Convert snake_case API keys to readable Title Case labels. */
  function capitalize(str) {
    return str.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
  }

  // ------------------------------------------------------------------
  // Field helpers
  // ------------------------------------------------------------------

  function getHostname(data) {
    if (!data) return '';
    const candidates = [data.hostname, data.host, data.name];
    for (const item of candidates) {
      if (item === null || item === undefined) continue;
      const text = String(item).trim();
      if (text && text !== '[object Object]' && text !== ipAddressEl.textContent) return text;
    }
    return '';
  }

  function getThreatCategories(data) {
    if (!data) return [];
    const candidates = [data.threat_category, data.categories]
      .filter(Boolean)
      .flat();
    const seen = new Set();
    const results = [];
    for (const item of candidates) {
      if (item === null || item === undefined) continue;
      const text = typeof item === 'object'
        ? String(item.category || item.name || item.label || item.type || item.n || '')
        : String(item);
      if (!text || /fmp/i.test(text) || text === '[object Object]') continue;
      const resolved = resolveTagName(text);
      if (!seen.has(resolved)) {
        seen.add(resolved);
        results.push(resolved);
      }
    }
    return results;
  }

  function getTags(data) {
    if (!data) return [];

    const extract = (arr) => {
      if (!Array.isArray(arr) || !arr.length) return null;
      const out = arr
        .map((item) => {
          if (item === null || item === undefined) return null;
          if (typeof item === 'object') {
            const text = item.category || item.name || item.label || item.type || item.n || JSON.stringify(item);
            return String(text);
          }
          return String(item);
        })
        .filter((v) => v && v !== '[object Object]' && !/fmp/i.test(v));
      return out.length ? out : null;
    };

    return extract(data.tags) || [];
  }

  // ------------------------------------------------------------------
  // Recent history
  // ------------------------------------------------------------------

  function addRecent(ip, resp) {
    chrome.storage.local.get({ recent: [] }, (data) => {
      const recent = data.recent;
      recent.unshift({ ip, resp, ts: Date.now() });
      if (recent.length > 20) recent.pop();
      chrome.storage.local.set({ recent }, () => renderRecent(recent));
    });

    // Also save the reputation score to the shared cache so icons on pages
    // show the same color after a lookup from the popup or context menu.
    const score = resp && resp.ok && resp.data ? resp.data.rep : null;
    const state = scoreToState(score);
    const cacheEntry = {
      state,
      score: typeof score === 'number' && Number.isFinite(score) ? score : null,
      tooltip: typeof score === 'number' && Number.isFinite(score)
        ? `Reputation score: ${score.toFixed(4)}`
        : 'No reputation data in NERD.',
      ts: Date.now()
    };
    chrome.storage.local.get('reputationCache', (data) => {
      const cache = data && data.reputationCache && typeof data.reputationCache === 'object'
        ? data.reputationCache
        : {};
      cache[ip] = cacheEntry;
      chrome.storage.local.set({ reputationCache: cache });
    });
  }

  function scoreToState(score) {
    if (score === undefined || score === null) return 'safe';
    if (typeof score !== 'number' || !Number.isFinite(score)) return 'error';
    if (score > 0.5) return 'malicious';
    if (score > 0.2) return 'elevated';
    return 'safe';
  }

  function renderRecent(recent) {
    clearChildren(resultsEl);

    if (!recent || !recent.length) {
      const li = document.createElement('li');
      li.style.color = '#888';
      li.style.fontSize = '12px';
      li.textContent = 'No recent lookups.';
      resultsEl.appendChild(li);
      return;
    }

    for (const r of recent) {
      resultsEl.appendChild(createRecentItem(r));
    }
  }

  function createRecentItem(r) {
    const li = document.createElement('li');
    li.style.cursor = 'pointer';

    const dot = document.createElement('span');
    dot.className = 'traffic-light ' + (r.resp && r.resp.ok ? getVerdictAndColor(r.resp.data).color : 'gray');
    dot.style.width = '8px';
    dot.style.height = '8px';
    dot.style.display = 'inline-block';
    dot.style.marginRight = '4px';
    dot.style.verticalAlign = 'middle';
    li.appendChild(dot);

    li.appendChild(document.createTextNode(r.ip + ' '));

    const tsSpan = document.createElement('span');
    tsSpan.style.color = '#888';
    tsSpan.style.fontSize = '11px';
    tsSpan.textContent = '(' + new Date(r.ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) + ')';
    li.appendChild(tsSpan);

    li.addEventListener('click', () => {
      ipInput.value = r.ip;
      if (r.resp && r.resp.ok) {
        showResultCard(r.ip, r.resp.data);
      } else {
        performLookup(r.ip);
      }
    });

    return li;
  }

  // ------------------------------------------------------------------
  // UI helpers
  // ------------------------------------------------------------------

  function setToggle(enabled) {
    toggleSwitch.checked = enabled;
    toggleStatus.textContent = enabled ? 'On' : 'Off';
  }

  function showStatus(message, durationMs) {
    statusEl.textContent = message;
    if (!durationMs) return;
    setTimeout(() => { statusEl.textContent = ''; }, durationMs);
  }

  function setText(el, text) {
    if (text) {
      el.textContent = text;
      el.classList.remove('hidden');
    } else {
      el.classList.add('hidden');
      el.textContent = '';
    }
  }

  function buildMissingApiKeyStatus() {
    clearChildren(statusEl);

    statusEl.appendChild(document.createTextNode('Missing API key. '));

    const a = document.createElement('a');
    a.href = '#';
    a.textContent = 'Open Settings';
    a.addEventListener('click', (e) => {
      e.preventDefault();
      openOptionsPage();
    });
    statusEl.appendChild(a);
  }

  function openOptionsPage() {
    if (chrome.runtime.openOptionsPage) {
      chrome.runtime.openOptionsPage();
    } else {
      window.open(chrome.runtime.getURL('options/options.html'));
    }
  }

  /**
   * Adds the active tab's hostname to the blocklist or allowlist.
   * If the site list mode is 'off', it switches to the matching mode first.
   * @param {'block'|'allow'} mode
   */
  async function addCurrentSiteToList(mode) {
    let tab;
    try {
      [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    } catch (_) {
      showSiteListStatus('Unable to read current tab.');
      return;
    }
    if (!tab || !tab.url) {
      showSiteListStatus('No active tab URL found.');
      return;
    }

    let hostname;
    try {
      hostname = new URL(tab.url).hostname;
    } catch (_) {
      showSiteListStatus('Current tab URL is not valid.');
      return;
    }
    if (!hostname) {
      showSiteListStatus('Current tab has no hostname.');
      return;
    }

    const storageKey = mode === 'allow' ? 'siteAllowlist' : 'siteBlocklist';
    const listName = mode === 'allow' ? 'allowlist' : 'blocklist';

    chrome.storage.local.get(
      { siteListMode: 'off', siteAllowlist: [], siteBlocklist: [] },
      (data) => {
        const currentList = data[storageKey] || [];
        const pattern = hostname + '*';
        if (currentList.includes(pattern)) {
          showSiteListStatus(`Site already in ${listName}.`);
          return;
        }

        const updates = { [storageKey]: [...currentList, pattern] };
        if (data.siteListMode === 'off') {
          updates.siteListMode = mode;
        }

        chrome.storage.local.set(updates, () => {
          showSiteListStatus(`Added to ${listName}: ${hostname}`);
          // Notify every tab whose URL might be affected so the content script
          // re-evaluates its block/allow state immediately.
          notifyTabsOfListChange(hostname);
        });
      }
    );
  }

  function showSiteListStatus(message, durationMs = 2500) {
    siteListActionStatus.textContent = message;
    if (!durationMs) return;
    setTimeout(() => { siteListActionStatus.textContent = ''; }, durationMs);
  }

  async function notifyTabsOfListChange(hostname) {
    try {
      const tabs = await chrome.tabs.query({});
      for (const tab of tabs) {
        if (!tab.id || !tab.url) continue;
        try {
          const tabHostname = new URL(tab.url).hostname;
          if (tabHostname === hostname || tabHostname.endsWith('.' + hostname)) {
            chrome.tabs.sendMessage(tab.id, { action: 'siteListChanged' });
          }
        } catch (_) {
          // Ignore tabs with invalid URLs.
        }
      }
    } catch (_) {
      // Tab may not be reachable; the content script will pick up the change
      // on its next storage sync anyway.
    }
  }

  async function copyToClipboard(text, button) {
    if (!text) return;
    const original = button.textContent;
    try {
      // Normalize line endings so Windows and Linux produce identical clipboard text.
      await navigator.clipboard.writeText(text.replace(/\r\n/g, '\n'));
      button.textContent = 'Copied!';
    } catch (_) {
      button.textContent = 'Failed';
    }
    setTimeout(() => { button.textContent = original; }, 1500);
  }

  function clearChildren(el) {
    while (el.firstChild) el.removeChild(el.firstChild);
  }
});
