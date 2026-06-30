/**
 * IP Detector - Content Script
 *
 * Injected into every web page matched by manifest.json.
 * Responsibilities:
 *   1. Read settings (detection on/off, highlight style, API base URL) from storage.
 *   2. Scan the DOM for IPv4 addresses using regex.
 *   3. Wrap detected IPs in clickable spans (icon or hover button mode).
 *   4. Watch for dynamic DOM mutations so single-page apps are covered.
 *   5. Expose a scan function so the popup can look up reputations for all
 *      visible IPs and update indicators next to each address.
 */

/* global chrome */

// ------------------------------------------------------------------
// Safety wrappers around chrome.* APIs
// ------------------------------------------------------------------
// When the extension is reloaded / updated, content scripts that are
// already injected on open pages become "orphaned". Any call to
// chrome.runtime or chrome.storage throws "Extension context invalidated".
// These wrappers prevent the unhandled exception from bubbling up.

function safeStorageSet(obj, cb) {
  try {
    chrome.storage.local.set(obj, cb);
  } catch (_) {
    if (typeof cb === 'function') cb();
  }
}

function safeStorageGet(keys, cb) {
  try {
    chrome.storage.local.get(keys, cb);
  } catch (_) {
    if (typeof cb === 'function') cb({});
  }
}

function safeSendMessage(msg) {
  try {
    chrome.runtime.sendMessage(msg);
  } catch (_) {}
}

/**
 * Attempts to open the extension popup directly from the content script.
 * openPopup() requires a user gesture, so this must be called inside a
 * click/keydown handler. Catches errors silently because not all browsers
 * expose chrome.action.openPopup to content scripts.
 */
function tryOpenPopupFromContentScript(ip) {
  // Route through the background service worker. The background checks
  // whether the popup is already open (via long-lived port tracking) and
  // skips chrome.action.openPopup() when it is, because on Windows calling
  // openPopup() while the popup is visible actually closes it.
  //
  // We deliberately do NOT call chrome.action.openPopup() directly from the
  // content script here — on Windows that call can close the popup instead
  // of opening it, and on most browsers the API is not exposed to content
  // scripts anyway.
  try {
    if (chrome && chrome.runtime && chrome.runtime.sendMessage) {
      chrome.runtime.sendMessage({ action: 'openPopup', ip }, () => {});
    }
  } catch (_) {}
}

function safeRuntimeSendMessageAsync(msg) {
  return new Promise((resolve, reject) => {
    try {
      chrome.runtime.sendMessage(msg, (resp) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
          return;
        }
        resolve(resp);
      });
    } catch (err) {
      reject(err);
    }
  });
}

// ------------------------------------------------------------------
// Extension-context sanity check
// ------------------------------------------------------------------
// When the extension reloads, orphaned content scripts must stop
// touching chrome APIs. Accessing chrome.runtime.id is the
// fastest, reliable way to know if the context is still alive.
function isExtensionValid() {
  try {
    return !!chrome.runtime.id;
  } catch (_) {
    return false;
  }
}

// ------------------------------------------------------------------
// Runtime toggles synced from chrome.storage
// ------------------------------------------------------------------
let detectionEnabled = true;
let styleMode = 'hover';
let siteListMode = 'off';
let siteBlocklist = [];
let siteAllowlist = [];

// ------------------------------------------------------------------
// React when the popup changes the site blocklist/allowlist
// ------------------------------------------------------------------
try {
  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message && message.action === 'siteListChanged') {
      safeStorageGet(
        { siteListMode: 'off', siteBlocklist: [], siteAllowlist: [] },
        (data) => {
          if (!isExtensionValid()) return;
          siteListMode = ['off', 'block', 'allow'].includes(data.siteListMode)
            ? data.siteListMode
            : 'off';
          siteBlocklist = Array.isArray(data.siteBlocklist) ? data.siteBlocklist : [];
          siteAllowlist = Array.isArray(data.siteAllowlist) ? data.siteAllowlist : [];
          reevaluateSiteBlockState();
        }
      );
    }

    if (message && message.action === 'scanAllVisibleIPs') {
      scanAllVisibleIPs()
        .then((result) => sendResponse(result))
        .catch((error) => sendResponse({ ok: false, status: error && error.message ? error.message : String(error) }));
      return true;
    }
  });
} catch (_) {
  // Extension context invalidated — listener cannot be registered.
}

function getIconUrl(name) {
  const file = `icons/icon-${name}.png`;
  return (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.getURL)
    ? chrome.runtime.getURL(file)
    : file;
}

const ICON_URLS = {
  gray: getIconUrl('gray'),
  green: getIconUrl('green'),
  orange: getIconUrl('orange'),
  red: getIconUrl('red'),
  purple: getIconUrl('purple')
};

const DEFAULT_ICON_URL = ICON_URLS.gray;

// ------------------------------------------------------------------
// Reputation state
// ------------------------------------------------------------------
const SCORE_THRESHOLDS = {
  safe: 0.2,
  caution: 0.5,
  elevated: 0.5
};

function stateToIconUrl(state) {
  switch (state) {
    case 'safe':
    case 'unknown':
      return ICON_URLS.green;
    case 'caution':
    case 'elevated':
      return ICON_URLS.orange;
    case 'malicious':
      return ICON_URLS.red;
    case 'error':
      return ICON_URLS.purple;
    case 'neutral':
    default:
      return ICON_URLS.gray;
  }
}

// ------------------------------------------------------------------
// Persistent reputation cache
// ------------------------------------------------------------------
// Results are stored in chrome.storage.local so icon colors survive
// page refresh. Each entry is timestamped and expires after CACHE_TTL_MS.
const CACHE_KEY = 'reputationCache';
const CACHE_TTL_MS = 1000 * 60 * 60; // 1 hour
const REPUTATION_CACHE = new Map();
let cacheLoaded = false;
let cacheSaveTimeout = null;
let scanInProgress = false;
let lastScanStatus = '';

function setScanStatus(text) {
  lastScanStatus = text || '';
}

function isCacheExpired(entry) {
  if (!entry || typeof entry.ts !== 'number') return true;
  return Date.now() - entry.ts > CACHE_TTL_MS;
}

function normalizeCacheEntry(entry) {
  if (!entry || typeof entry !== 'object') return null;
  const result = entry.result || entry;
  if (!result || typeof result !== 'object') return null;
  if (typeof result.state !== 'string') return null;
  return {
    state: result.state,
    score: typeof result.score === 'number' && Number.isFinite(result.score) ? result.score : null,
    tooltip: typeof result.tooltip === 'string' ? result.tooltip : `Reputation: ${result.state}`,
    ts: typeof entry.ts === 'number' ? entry.ts : Date.now()
  };
}

function loadCacheFromStorage() {
  return new Promise((resolve) => {
    safeStorageGet(CACHE_KEY, (data) => {
      try {
        const raw = data && data[CACHE_KEY];
        if (raw && typeof raw === 'object') {
          for (const [ip, entry] of Object.entries(raw)) {
            if (!isValidIP(ip)) continue;
            const normalized = normalizeCacheEntry(entry);
            if (normalized && !isCacheExpired(normalized)) {
              REPUTATION_CACHE.set(ip, normalized);
            }
          }
        }
      } catch (_) {
        // Ignore malformed storage data.
      }
      cacheLoaded = true;
      resolve();
    });
  });
}

function saveCacheToStorage() {
  if (!isExtensionValid()) return;
  if (cacheSaveTimeout) {
    clearTimeout(cacheSaveTimeout);
  }
  cacheSaveTimeout = setTimeout(() => {
    cacheSaveTimeout = null;
    if (!isExtensionValid()) return;
    const serializable = {};
    for (const [ip, entry] of REPUTATION_CACHE.entries()) {
      serializable[ip] = entry;
    }
    safeStorageSet({ [CACHE_KEY]: serializable });
  }, 250);
}

function getCachedResult(ip) {
  const entry = REPUTATION_CACHE.get(ip);
  if (!entry) return undefined;
  if (isCacheExpired(entry)) {
    REPUTATION_CACHE.delete(ip);
    return undefined;
  }
  return entry;
}

function setCachedResult(ip, result) {
  const entry = {
    state: result.state,
    score: typeof result.score === 'number' && Number.isFinite(result.score) ? result.score : null,
    tooltip: result.tooltip || `Reputation: ${result.state}`,
    ts: Date.now()
  };
  REPUTATION_CACHE.set(ip, entry);
  saveCacheToStorage();
}

function createNerdIcon(ip, hidden) {
  const icon = document.createElement('img');
  icon.className = 'ip-detector-icon';
  icon.src = DEFAULT_ICON_URL;
  icon.alt = 'Lookup IP';
  icon.title = 'Search this IP in NERD';
  icon.setAttribute('role', 'button');
  icon.setAttribute('tabindex', '0');
  icon.setAttribute('aria-label', 'Lookup IP ' + ip);
  icon.dataset.ip = ip;
  icon.dataset.reputation = 'neutral';
  if (hidden) icon.classList.add('ip-detector-icon-hidden');

  // Keep a direct keyboard listener so Enter/Space on a focused icon works.
  icon.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      event.stopPropagation();
      handleIconClick(icon);
    }
  });

  return icon;
}

// Central handler for clicking an icon. It is invoked both by the delegated
// document listener below and by the keyboard listener above. Using delegation
// makes clicks work even when frameworks such as Grafana's React table
// recreate or move the icon element, because the listener lives on a stable
// ancestor rather than on the per-icon element.
function handleIconClick(icon) {
  const ip = icon.dataset.ip;
  if (!ip) return;

  // Send the openPopup message immediately while we are still inside the
  // user-gesture window. openPopup() requires a user gesture and the gesture
  // expires quickly; waiting for chrome.storage.local.set to finish can push
  // us past that window and cause "The popup could not be opened." The popup
  // reads pendingIp both on startup and via the storage.onChanged listener,
  // so it is safe to write it in parallel.
  tryOpenPopupFromContentScript(ip);

  // Write pendingIp immediately as well. The popup will either read it on
  // load or pick it up through the storage change event if it was already
  // open.
  safeStorageSet({ pendingIp: ip });

  // After a short delay, look up the IP and refresh the icon.
  setTimeout(() => {
    lookupReputationForIcon(ip, icon).catch(() => {
      // Individual lookup failed; the icon stays in its current state.
    });
  }, 150);
}

function isPointInElement(x, y, element) {
  if (!element || !element.getBoundingClientRect) return false;
  const rect = element.getBoundingClientRect();
  return x >= rect.left && x <= rect.right && y >= rect.top && y <= rect.bottom;
}

function findIconAtPoint(x, y) {
  // Try the native hit-test target first.
  let target = document.elementFromPoint && document.elementFromPoint(x, y);
  if (target) {
    const icon = target.closest && target.closest('.ip-detector-icon');
    if (icon) return icon;
  }

  // Fallback: some table libraries (e.g. Grafana) report the wrapper/cell as
  // the click target even though the icon is visible. Check whether the point
  // falls inside any icon's bounding box.
  for (const wrapper of document.querySelectorAll('.ip-detector-wrapper')) {
    const icon = wrapper.iconElement || wrapper.querySelector('.ip-detector-icon');
    if (icon && isPointInElement(x, y, icon)) return icon;
  }
  return null;
}

// Delegated click handler for all icons. This catches clicks on icons that
// were recreated by the page after the initial listener was attached, and also
// works around table libraries where the icon is visible but not the actual
// hit-test target.
document.addEventListener('click', (event) => {
  const icon = findIconAtPoint(event.clientX, event.clientY);
  if (!icon) return;

  event.preventDefault();
  event.stopPropagation();
  handleIconClick(icon);
}, true);

// Cursor feedback: some table cells report the wrapper/cell as the hover target
// instead of the icon, so the icon's cursor:pointer style is not applied.
// When the pointer is inside an icon's visible box, set cursor:pointer on the
// actual hit target element (usually the wrapper or cell) with !important so
// it wins over any page-level cursor style.
let lastCursorTarget = null;
function setIconCursor(target, active) {
  if (!target) return;
  if (active) {
    if (target.style.cursor !== 'pointer') {
      target.dataset.ipDetectorCursorOriginal = target.style.cursor;
      target.style.setProperty('cursor', 'pointer', 'important');
    }
  } else if (target.dataset.ipDetectorCursorOriginal !== undefined) {
    target.style.cursor = target.dataset.ipDetectorCursorOriginal;
    delete target.dataset.ipDetectorCursorOriginal;
  }
}

document.addEventListener('pointermove', (event) => {
  const icon = findIconAtPoint(event.clientX, event.clientY);
  const hitTarget = document.elementFromPoint && document.elementFromPoint(event.clientX, event.clientY);

  if (icon && hitTarget && hitTarget !== icon) {
    if (lastCursorTarget && lastCursorTarget !== hitTarget) {
      setIconCursor(lastCursorTarget, false);
    }
    lastCursorTarget = hitTarget;
    setIconCursor(hitTarget, true);
  } else {
    if (lastCursorTarget) {
      setIconCursor(lastCursorTarget, false);
      lastCursorTarget = null;
    }
  }
});

async function lookupReputationForIcon(ip, icon) {
  // Always force a fresh lookup when the user explicitly clicks an icon,
  // so a stale/error/purple icon can update after a successful scan.
  // Keep the existing color while loading; only update once we have a result.
  const previousTooltip = icon.title || `Reputation: ${icon.dataset.reputation || 'neutral'}`;
  icon.title = 'Looking up reputation…';

  // Use the same lookupIp endpoint that the popup uses; it is known to work
  // and returns the full IP record including the reputation score.
  const result = await fetchIpReputation(ip);
  if (!result.ok) {
    const errorResult = { state: 'error', score: null, tooltip: describeError(result.error) };
    setCachedResult(ip, errorResult);
    applyReputation(ip, errorResult, [icon.closest('.ip-detector-wrapper')].filter(Boolean));
    return;
  }

  const score = result.score;
  const built = buildReputationResult(score);
  setCachedResult(ip, built);
  applyReputation(ip, built, [icon.closest('.ip-detector-wrapper')].filter(Boolean));
}

async function fetchIpReputation(ip) {
  try {
    const resp = await safeRuntimeSendMessageAsync({ action: 'lookupIp', ip });
    if (!resp) {
      return { ok: false, error: 'No response from extension background.' };
    }
    // A 404 / not-found response means the IP has no data in NERD.
    // Treat that as safe (green) instead of an error (purple).
    if (!resp.ok) {
      const error = String(resp.error || '');
      if (error === '404' || /not found/i.test(error) || /no data/i.test(error)) {
        return { ok: true, score: null };
      }
      return { ok: false, error: resp.error };
    }
    // The popup's lookupIp returns the full IP record. The reputation score
    // may be in resp.data.rep, resp.data.score, or may be missing entirely.
    const data = resp.data || {};
    const score = extractScoreFromData(data);
    return { ok: true, score };
  } catch (err) {
    return { ok: false, error: err && err.message ? err.message : String(err) };
  }
}

function extractScoreFromData(data) {
  if (data === null || data === undefined) return null;
  if (typeof data === 'number' && Number.isFinite(data)) return data;
  if (typeof data === 'object') {
    if (typeof data.rep === 'number' && Number.isFinite(data.rep)) return data.rep;
    if (typeof data.score === 'number' && Number.isFinite(data.score)) return data.score;
    if (typeof data.reputation === 'number' && Number.isFinite(data.reputation)) return data.reputation;
  }
  if (typeof data === 'string') {
    const trimmed = data.trim();
    if (trimmed === '') return null;
    const parsed = Number(trimmed);
    if (Number.isFinite(parsed)) return parsed;
  }
  return null;
}

// ------------------------------------------------------------------
// Settings hydration
// ------------------------------------------------------------------
/**
 * Determines whether the current page's hostname matches a user-defined
 * blocklist entry. Patterns may be plain hostnames, `*.example.com` for
 * subdomains, or simple `*` wildcards at the start/end of a URL pattern.
 */
function isCurrentSiteBlocked() {
  try {
    const hostname = location.hostname || '';
    const href = location.href || '';
    if (siteListMode === 'off') return false;
    if (siteListMode === 'allow') {
      // Allowlist mode: detection is disabled UNLESS the site matches the allowlist.
      for (const pattern of siteAllowlist) {
        if (!pattern) continue;
        if (patternMatchesSite(pattern, hostname, href)) return false;
      }
      return true;
    }
    // Blocklist mode (default): detection is disabled if the site matches the blocklist.
    for (const pattern of siteBlocklist) {
      if (!pattern) continue;
      if (patternMatchesSite(pattern, hostname, href)) return true;
    }
  } catch (_) {
    // Fail closed (assume not blocked) on unexpected errors.
  }
  return false;
}

function patternMatchesSite(pattern, hostname, href) {
  if (pattern.includes('/')) {
    return matchWildcardPattern(pattern, href);
  }
  return matchWildcardPattern(pattern, hostname);
}

function matchWildcardPattern(pattern, str) {
  const escaped = pattern.replace(/[.+^${}()|[\]\\?]/g, '\\$&');
  const regex = new RegExp('^' + escaped.replace(/\*/g, '.*') + '$', 'i');
  return regex.test(str);
}

async function initDetectionState() {
  if (!isExtensionValid()) return;

  try {
    await loadCacheFromStorage();
  } catch (_) {
    // Cache load is best-effort; continue without it.
  }

  try {
    chrome.storage.local.get(
      { detectionEnabled: true, styleMode: 'hover', siteListMode: 'off', siteBlocklist: [], siteAllowlist: [] },
      (data) => {
        if (!isExtensionValid()) return;

        detectionEnabled = data.detectionEnabled;
        styleMode = data.styleMode || 'hover';
        siteListMode = ['off', 'block', 'allow'].includes(data.siteListMode) ? data.siteListMode : 'off';
        siteBlocklist = Array.isArray(data.siteBlocklist) ? data.siteBlocklist : [];
        siteAllowlist = Array.isArray(data.siteAllowlist) ? data.siteAllowlist : [];

        if (isCurrentSiteBlocked()) {
          detectionEnabled = false;
        }

        if (document.readyState === 'loading') {
          document.addEventListener('DOMContentLoaded', runOrUpdate);
        } else {
          runOrUpdate();
        }

        safeSendMessage({
          action: 'detectionStateChanged',
          enabled: detectionEnabled
        });
      }
    );
  } catch (_) {
    // Extension context invalidated — silently stop.
  }
}

// Lightweight re-scan for IPs added after page load (e.g. DataTables).
function rescan() {
  if (!document.body || !detectionEnabled || !isExtensionValid() || isCurrentSiteBlocked()) return;
  walk(document.body);
  reapplyInlineFallback();
}

const RESCAN_DELAYS = [1000, 3000, 6000, 10000, 15000, 25000];
function scheduleRescans() {
  RESCAN_DELAYS.forEach((delay) => {
    setTimeout(() => rescan(), delay);
  });
}

function runOrUpdate() {
  if (detectionEnabled && !isCurrentSiteBlocked()) {
    initIPDetector();
    observeMutations();
    scheduleRescans();
  } else {
    updateDisabledVisualState();
    if (mutationObserver) {
      mutationObserver.disconnect();
      mutationObserver = null;
    }
  }
}

// Remove all wrappers and restore plain text nodes when user disables detection
function updateDisabledVisualState() {
  document.querySelectorAll('.ip-detector-wrapper').forEach((w) => {
    const text = w.querySelector('.ip-detector-text');
    if (text && w.parentNode) {
      w.replaceWith(document.createTextNode(text.textContent));
    } else {
      w.remove();
    }
  });

  // Clean up any leftover plain-text spans from previous unwraps.
  document.querySelectorAll('.ip-detector-text').forEach((el) => {
    if (!el.closest('.ip-detector-wrapper')) {
      el.replaceWith(document.createTextNode(el.textContent));
    }
  });
}

// ==================================================================
// IP detection
// ==================================================================

// IPv4 regex — word-boundaries prevent partial matches.
// A trailing :port is intentionally included in the match; a trailing /mask
// (CIDR) is intentionally excluded by checking the following character.
// A trailing .in-addr.arpa (reverse DNS) is also excluded.
const ipv4Regex =
  /\b(?:25[0-5]|2[0-4]\d|1?\d{1,2})(?:\.(?:25[0-5]|2[0-4]\d|1?\d{1,2})){3}(?::\d+)?\b(?!\/)(?!\.in-addr\.arpa)/gi;

// Never descend into elements that would spam or break page functionality
function shouldSkipElement(element) {
  if (
    !element ||
    typeof element.closest !== 'function' ||
    typeof element.getAttribute !== 'function'
  ) {
    return true;
  }

  const skipTags = [
    'SCRIPT',
    'STYLE',
    'NOSCRIPT',
    'IFRAME',
    'OBJECT',
    'TEXTAREA',
    'AUDIO',
    'VIDEO',
    'SVG'
  ];
  if (skipTags.includes(element.tagName)) return true;

  // Already wrapped or inside inline editor
  if (element.closest('[contenteditable="true"]')) return true;
  if (element.closest('.ip-detector-wrapper')) return true;
  if (element.classList && element.classList.contains('ip-detector-wrapper'))
    return true;

  return false;
}

// Detect whether an absolutely positioned icon next to this wrapper would be
// clipped by an ancestor with overflow:hidden / ellipsis, or sits inside a
// table cell where clipping is common. In those cases we render the icon
// inline so it stays visible (e.g. ThreatFox table cells).
function needsInlineIcon(wrapper) {
  if (typeof window === 'undefined' || !window.getComputedStyle) return false;
  let el = wrapper.parentElement;
  while (el && el !== document.body) {
    const style = window.getComputedStyle(el);
    if (
      style.overflow === 'hidden' ||
      style.overflowX === 'hidden' ||
      style.overflowY === 'hidden' ||
      style.textOverflow === 'ellipsis' ||
      style.whiteSpace === 'nowrap' ||
      el.tagName === 'TD' ||
      el.tagName === 'TH'
    ) {
      return true;
    }
    el = el.parentElement;
  }
  return false;
}

// Some pages (e.g. DataTables) apply clipping styles after the wrappers are
// created. Re-evaluate existing wrappers and switch them to inline layout.
function reapplyInlineFallback() {
  document.querySelectorAll('.ip-detector-wrapper:not(.layout-inline-icon)').forEach((w) => {
    if (needsInlineIcon(w)) w.classList.add('layout-inline-icon');
  });
}

// Collect all matching IPv4 addresses from a text string, sorted by position.
// If a match includes :port, the displayed token keeps the port while the
// lookup key is only the bare IP.
function findIPMatches(text) {
  const matches = [];
  let m;

  ipv4Regex.lastIndex = 0;
  while ((m = ipv4Regex.exec(text)) !== null) {
    const token = m[0];
    const display = token;
    const lookup = token.split(':')[0];
    matches.push({ ip: lookup, display, index: m.index, len: token.length });
  }

  return matches.sort((a, b) => a.index - b.index);
}

// ------------------------------------------------------------------
// DOM construction
// ------------------------------------------------------------------

// Build a clickable wrapper around a single IP address.
function createIPWrapper(ip, display) {
  const wrapper = document.createElement('span');
  wrapper.className = 'ip-detector-wrapper';

  // The original text node is preserved as a child span.
  // `display` may include :port; the icon lookup still uses bare `ip`.
  const ipLabel = document.createElement('span');
  ipLabel.className = 'ip-detector-text';
  ipLabel.textContent = display || ip;
  wrapper.appendChild(ipLabel);

  const isHover = styleMode === 'hover';
  const icon = createNerdIcon(ip, isHover);
  wrapper.iconElement = icon;
  wrapper.appendChild(icon);

  // Restore cached reputation color immediately if available.
  const cached = getCachedResult(ip);
  if (cached) {
    setIconReputation(icon, cached);
  }

  if (isHover) {
    wrapper.classList.add('style-hover');
    wrapper.title = 'Hover to lookup ' + ip;
    setupHoverPersistence(wrapper, icon);
  }

  // If the wrapper sits inside a clipped container (e.g. a DataTables
  // cell with overflow:hidden), render the icon inline so it is not cut off.
  if (needsInlineIcon(wrapper)) {
    wrapper.classList.add('layout-inline-icon');
  }

  return wrapper;
}

// Make the icon stay visible while the cursor moves from the IP text to
// the icon, even slowly. CSS hover already reveals it; JS just adds a tiny
// hide delay to prevent flicker if the cursor briefly leaves both elements.
function setupHoverPersistence(wrapper, icon) {
  let hoverCount = 0;
  let hideTimeout = null;

  function onEnter() {
    hoverCount += 1;
    if (hideTimeout) {
      clearTimeout(hideTimeout);
      hideTimeout = null;
    }
    icon.classList.remove('ip-detector-icon-hidden');
  }

  function onLeave() {
    hoverCount = Math.max(0, hoverCount - 1);
    if (hoverCount === 0 && !hideTimeout) {
      hideTimeout = setTimeout(() => {
        hideTimeout = null;
        if (hoverCount === 0) icon.classList.add('ip-detector-icon-hidden');
      }, 180);
    }
  }

  wrapper.addEventListener('mouseenter', onEnter);
  wrapper.addEventListener('mouseleave', onLeave);
  icon.addEventListener('mouseenter', onEnter);
  icon.addEventListener('mouseleave', onLeave);
}

// Rebuild every already-wrapped IP on the page (used when styleMode changes)
function refreshWrappers() {
  document.querySelectorAll('.ip-detector-wrapper').forEach((w) => {
    const text = w.querySelector('.ip-detector-text');
    if (text && w.parentNode) {
      const fresh = createIPWrapper(w.dataset.ip || text.textContent, text.textContent);
      w.replaceWith(fresh);
    }
  });
}

// ------------------------------------------------------------------
// Text-node processing
// ------------------------------------------------------------------

function handleTextNode(textNode) {
  const text = textNode.nodeValue;
  const matches = findIPMatches(text);
  if (!matches.length) return;

  const fragment = document.createDocumentFragment();
  let lastIndex = 0;

  for (const match of matches) {
    if (match.index < lastIndex) continue;

    fragment.appendChild(document.createTextNode(text.slice(lastIndex, match.index)));
    const wrapper = createIPWrapper(match.ip, match.display);
    wrapper.dataset.ip = match.ip;
    fragment.appendChild(wrapper);

    lastIndex = match.index + match.len;
  }
  fragment.appendChild(document.createTextNode(text.slice(lastIndex)));
  textNode.parentNode.replaceChild(fragment, textNode);
}

// Recursive DFS over the DOM tree, skipping non-interesting elements
function walk(node) {
  let child = node.firstChild;
  while (child) {
    const next = child.nextSibling; // cache because mutations may change children
    if (child.nodeType === Node.TEXT_NODE) {
      handleTextNode(child);
    } else if (
      child.nodeType === Node.ELEMENT_NODE &&
      !shouldSkipElement(child)
    ) {
      walk(child);
    }
    child = next;
  }
}

// ------------------------------------------------------------------
// Init / teardown
// ------------------------------------------------------------------

function initIPDetector() {
  document.querySelectorAll('.ip-detector-wrapper').forEach((w) => {
    const text = w.querySelector('.ip-detector-text');
    if (text && w.parentNode) {
      w.replaceWith(document.createTextNode(text.textContent));
    } else {
      w.remove();
    }
  });

  // Clean up orphaned .ip-detector-text spans so they are not wrapped again.
  document.querySelectorAll('.ip-detector-text').forEach((el) => {
    if (!el.closest('.ip-detector-wrapper')) {
      el.replaceWith(document.createTextNode(el.textContent));
    }
  });

  if (document.body) {
    walk(document.body);
  }
}

// ------------------------------------------------------------------
// MutationObserver — catches single-page-app DOM updates
// ------------------------------------------------------------------
let mutationObserver = null;

function observeMutations() {
  if (typeof MutationObserver === 'undefined') return;
  if (isCurrentSiteBlocked()) return;
  if (mutationObserver) mutationObserver.disconnect();

  mutationObserver = new MutationObserver((mutations) => {
    if (!isExtensionValid() || isCurrentSiteBlocked()) return;

    let shouldProcess = false;
    for (const mutation of mutations) {
      if (mutation.type === 'characterData') {
        const parent = mutation.target.parentNode;
        if (
          parent &&
          !parent.closest('.ip-detector-wrapper') &&
          !shouldSkipElement(parent)
        ) {
          shouldProcess = true;
        }
        continue;
      }
      for (const node of mutation.addedNodes) {
        if (node.nodeType === Node.TEXT_NODE) {
          const parent = node.parentNode;
          if (
            parent &&
            !parent.closest('.ip-detector-wrapper') &&
            !shouldSkipElement(parent)
          )
            shouldProcess = true;
        } else if (node.nodeType === Node.ELEMENT_NODE) {
          if (!node.closest('.ip-detector-wrapper') && !shouldSkipElement(node))
            shouldProcess = true;
        }
        if (shouldProcess) break;
      }
      if (shouldProcess) break;
    }
    if (!shouldProcess) return;

    mutationObserver.disconnect();

    for (const mutation of mutations) {
      if (mutation.type === 'characterData') {
        const parent = mutation.target.parentNode;
        if (
          parent &&
          !parent.closest('.ip-detector-wrapper') &&
          !shouldSkipElement(parent)
        ) {
          handleTextNode(mutation.target);
        }
        continue;
      }
      for (const node of mutation.addedNodes) {
        if (
          node.nodeType === Node.TEXT_NODE &&
          node.parentNode &&
          !node.parentNode.closest('.ip-detector-wrapper') &&
          !shouldSkipElement(node.parentNode)
        ) {
          handleTextNode(node);
        } else if (
          node.nodeType === Node.ELEMENT_NODE &&
          !node.closest('.ip-detector-wrapper') &&
          !shouldSkipElement(node)
        ) {
          walk(node);
        }
      }
    }
    // Apply inline icon fallback after any DOM change that may introduce
    // new wrappers or new clipping styles (e.g. DataTables re-rendering).
    reapplyInlineFallback();

    if (document.body && isExtensionValid()) {
      mutationObserver.observe(document.body, {
        childList: true,
        subtree: true,
        characterData: true
      });
    }
  });

  if (document.body && isExtensionValid()) {
    mutationObserver.observe(document.body, {
      childList: true,
      subtree: true,
      characterData: true
    });
  }
}

// ------------------------------------------------------------------
// Scan logic (triggered from the popup)
// ------------------------------------------------------------------

async function scanAllVisibleIPs() {
  if (scanInProgress) {
    return { ok: false, status: lastScanStatus || 'Scan already in progress.' };
  }
  if (isCurrentSiteBlocked()) {
    return { ok: false, status: 'IP detection is disabled on this site.' };
  }

  const wrappers = collectVisibleIPWrappers();
  const uniqueIps = new Set();
  const wrappersByIp = new Map();

  for (const wrapper of wrappers) {
    const ip = wrapper.dataset.ip;
    if (!ip || !isValidIP(ip)) continue;
    uniqueIps.add(ip);
    if (!wrappersByIp.has(ip)) wrappersByIp.set(ip, []);
    wrappersByIp.get(ip).push(wrapper);
  }

  if (uniqueIps.size === 0) {
    const message = 'No visible IP addresses found.';
    setScanStatus(message);
    return { ok: true, status: message, scanned: 0, fromCache: 0 };
  }

  const statusPrefix = `Scanning ${uniqueIps.size} unique IP${uniqueIps.size === 1 ? '' : 's'}…`;
  setScanStatus(statusPrefix);
  scanInProgress = true;

  // Separate cached and uncached IPs first, then apply cached results in
  // chunks so a page with many cached IPs does not block the main thread.
  const cachedIps = [];
  const ipsToFetch = [];
  for (const ip of uniqueIps) {
    const cached = getCachedResult(ip);
    if (cached) {
      cachedIps.push(ip);
    } else {
      ipsToFetch.push(ip);
    }
  }

  // Only reset icons that actually need a network lookup.
  setIconsToNeutral(new Set(ipsToFetch), wrappersByIp);
  await applyCachedResultsInChunks(cachedIps, wrappersByIp);

  if (ipsToFetch.length === 0) {
    const message = `Updated from cache (${uniqueIps.size} IP${uniqueIps.size === 1 ? '' : 's'}).`;
    setScanStatus(message);
    scanInProgress = false;
    return { ok: true, status: message, scanned: 0, fromCache: uniqueIps.size };
  }

  try {
    const startTime = performance.now();
    const bulkResult = await fetchBulkReputation(ipsToFetch);
    const elapsed = Math.round(performance.now() - startTime);

    if (!bulkResult.ok) {
      // Apply a generic error state to every IP that was supposed to be fetched.
      const errorResult = { state: 'error', score: null, tooltip: describeError(bulkResult.error) };
      await applyReputationInChunks(ipsToFetch, errorResult, wrappersByIp);
      const message = `Error: ${bulkResult.error}`;
      setScanStatus(message);
      return { ok: false, status: message };
    }

    await applyReputationInBatches(ipsToFetch, bulkResult.scores, wrappersByIp);

    const fetchedCount = ipsToFetch.length;
    const message = `Scanned ${fetchedCount} IP${fetchedCount === 1 ? '' : 's'} in ${elapsed}ms.`;
    setScanStatus(message);
    return { ok: true, status: message, scanned: fetchedCount, fromCache: uniqueIps.size - fetchedCount };
  } finally {
    scanInProgress = false;
  }
}

function collectVisibleIPWrappers() {
  if (!document.body) return [];
  return Array.from(document.querySelectorAll('.ip-detector-wrapper'));
}

function setIconsToNeutral(ipSet, wrappersByIp) {
  // Instead of setting every icon to gray immediately, only reset icons that
  // do not already have a cached result. This avoids a massive synchronous
  // DOM update at the start of a large bulk scan.
  for (const ip of ipSet) {
    if (getCachedResult(ip)) continue;
    for (const wrapper of wrappersByIp.get(ip) || []) {
      const icon = wrapper.iconElement;
      if (icon) setIconReputation(icon, { state: 'neutral', tooltip: 'Scanning reputation…' });
    }
  }
}

/**
 * Yields control back to the browser so the UI can paint between chunks of
 * DOM updates. Returns a promise that resolves after the next animation frame
 * (or a short timeout for browsers that do not support requestAnimationFrame).
 */
function yieldToMain() {
  return new Promise((resolve) => {
    if (typeof requestAnimationFrame === 'function') {
      requestAnimationFrame(() => resolve());
    } else {
      setTimeout(resolve, 0);
    }
  });
}

/**
 * Applies a single reputation result to many IPs in small chunks, yielding
 * between chunks so the page stays responsive.
 */
async function applyReputationInChunks(ips, result, wrappersByIp, chunkSize = 50) {
  for (let i = 0; i < ips.length; i += chunkSize) {
    const chunk = ips.slice(i, i + chunkSize);
    for (const ip of chunk) {
      setCachedResult(ip, result);
      applyReputation(ip, result, wrappersByIp.get(ip) || []);
    }
    if (i + chunkSize < ips.length) {
      // eslint-disable-next-line no-await-in-loop
      await yieldToMain();
    }
  }
}

/**
 * Applies per-IP reputation results in small batches, yielding between batches
 * to keep the page responsive during large bulk scans.
 */
async function applyReputationInBatches(ips, scores, wrappersByIp, chunkSize = 50) {
  for (let i = 0; i < ips.length; i += chunkSize) {
    const chunk = ips.slice(i, i + chunkSize);
    for (const ip of chunk) {
      const score = scores[ip];
      const result = buildReputationResult(score);
      setCachedResult(ip, result);
      applyReputation(ip, result, wrappersByIp.get(ip) || []);
    }
    if (i + chunkSize < ips.length) {
      // eslint-disable-next-line no-await-in-loop
      await yieldToMain();
    }
  }
}

/**
 * Applies cached reputation results to many IPs in small chunks, yielding
 * between chunks so a page with many cached IPs does not block the UI.
 */
async function applyCachedResultsInChunks(ips, wrappersByIp, chunkSize = 50) {
  for (let i = 0; i < ips.length; i += chunkSize) {
    const chunk = ips.slice(i, i + chunkSize);
    for (const ip of chunk) {
      const cached = getCachedResult(ip);
      if (cached) {
        applyReputation(ip, cached, wrappersByIp.get(ip) || []);
      }
    }
    if (i + chunkSize < ips.length) {
      // eslint-disable-next-line no-await-in-loop
      await yieldToMain();
    }
  }
}

async function fetchBulkReputation(ips) {
  try {
    const resp = await safeRuntimeSendMessageAsync({ action: 'lookupRepBulk', ips });
    if (!resp) {
      return { ok: false, error: 'No response from extension background.' };
    }
    if (!resp.ok) {
      return { ok: false, error: resp.error };
    }
    return { ok: true, scores: resp.scores || {} };
  } catch (err) {
    return { ok: false, error: err && err.message ? err.message : String(err) };
  }
}

function buildReputationResult(score) {
  // No data in NERD is treated as safe (green) per user request.
  if (score === undefined || score === null) {
    return { state: 'safe', score: null, tooltip: 'No reputation data in NERD.' };
  }
  if (typeof score !== 'number' || !Number.isFinite(score)) {
    return { state: 'error', score: null, tooltip: 'Invalid reputation score returned.' };
  }
  return { state: scoreToState(score), score, tooltip: `Reputation score: ${score.toFixed(4)}` };
}

function describeError(error) {
  if (!error) return 'Reputation lookup failed.';
  if (error === 'Missing API key') return 'API key is missing. Open extension settings.';
  if (error === '404') return 'IP not found in reputation database.';
  if (error === '400') return 'IP format not recognized by API.';
  if (error === 'Request timed out') return 'Request timed out. Network or API may be slow.';
  if (/^HTTP \d+/.test(error)) return `Server error: ${error}`;
  if (/rate limited/i.test(error)) return 'Rate limited. Retries exhausted.';
  return String(error);
}

function scoreToState(score) {
  if (score <= SCORE_THRESHOLDS.safe) return 'safe';
  if (score <= SCORE_THRESHOLDS.caution) return 'elevated';
  return 'malicious';
}

function applyReputation(ip, result, wrappers) {
  for (const wrapper of wrappers) {
    const icon = wrapper.iconElement;
    if (icon) setIconReputation(icon, result);
  }
}

function setIconReputation(icon, result) {
  if (icon.dataset.reputation === result.state && icon.title === (result.tooltip || `Reputation: ${result.state}`)) {
    return;
  }
  icon.dataset.reputation = result.state;
  icon.src = stateToIconUrl(result.state);
  // Remove any previous inline tint/shadow so only the clean PNG is visible.
  icon.style.backgroundColor = '';
  icon.style.borderRadius = '';
  icon.style.filter = '';
  icon.title = result.tooltip || `Reputation: ${result.state}`;
  icon.classList.remove('ip-detector-icon-hidden');
}

// ------------------------------------------------------------------
// IP validation
// ------------------------------------------------------------------

function isValidIP(ip) {
  if (typeof ip !== 'string' || !ip) return false;
  return isValidIPv4(ip);
}

function isValidIPv4(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return false;
  return parts.every((part) => {
    const num = Number(part);
    return part !== '' && String(num) === part && num >= 0 && num <= 255;
  });
}

// ------------------------------------------------------------------
// Startup
// ------------------------------------------------------------------
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => initDetectionState());
} else {
  initDetectionState();
}

// ------------------------------------------------------------------
// Respond to settings changes pushed from the popup
// ------------------------------------------------------------------
try {
  chrome.storage.onChanged.addListener((changes) => {
    if (!isExtensionValid()) return;

    if (changes.detectionEnabled) {
      const wasEnabled = detectionEnabled;
      detectionEnabled = changes.detectionEnabled.newValue;
      if (!detectionEnabled) {
        updateDisabledVisualState();
        if (mutationObserver) {
          mutationObserver.disconnect();
          mutationObserver = null;
        }
      } else if (detectionEnabled && !wasEnabled) {
        if (!isCurrentSiteBlocked()) {
          initIPDetector();
          observeMutations();
        }
      }
    }
    if (changes.siteListMode) {
      const newMode = changes.siteListMode.newValue;
      siteListMode = ['off', 'block', 'allow'].includes(newMode) ? newMode : 'off';
      reevaluateSiteBlockState();
    }
    if (changes.siteBlocklist) {
      siteBlocklist = Array.isArray(changes.siteBlocklist.newValue)
        ? changes.siteBlocklist.newValue
        : [];
      reevaluateSiteBlockState();
    }
    if (changes.siteAllowlist) {
      siteAllowlist = Array.isArray(changes.siteAllowlist.newValue)
        ? changes.siteAllowlist.newValue
        : [];
      reevaluateSiteBlockState();
    }
    if (changes.styleMode) {
      styleMode = changes.styleMode.newValue;
      refreshWrappers();
    }
  });
} catch (_) {
  // Extension context invalidated — listener never registered.
}

function reevaluateSiteBlockState() {
  const wasBlocked = !detectionEnabled || document.querySelectorAll('.ip-detector-wrapper').length === 0;
  const blocked = isCurrentSiteBlocked();
  if (blocked) {
    updateDisabledVisualState();
    if (mutationObserver) {
      mutationObserver.disconnect();
      mutationObserver = null;
    }
  } else if (wasBlocked && !blocked && detectionEnabled) {
    initIPDetector();
    observeMutations();
    scheduleRescans();
  }
}
