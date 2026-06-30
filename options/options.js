/**
 * NERD IP info - Options page script
 *
 * Loads and persists the extension settings from chrome.storage.local.
 */

/* global chrome */

document.addEventListener('DOMContentLoaded', () => {
  const apiTokenInput = document.getElementById('apiToken');
  const saveTokenBtn  = document.getElementById('saveToken');
  const tokenStatus   = document.getElementById('tokenStatus');
  const styleModeSelect = document.getElementById('styleMode');
  const clearHistoryBtn = document.getElementById('clearHistory');
  const clearStatus   = document.getElementById('clearStatus');
  const clearCacheBtn = document.getElementById('clearCache');
  const cacheStatus   = document.getElementById('cacheStatus');

  // Site list controls
  const siteListModeSelect = document.getElementById('siteListMode');
  const siteListInput = document.getElementById('siteList');
  const saveSiteListBtn = document.getElementById('saveSiteList');
  const clearSiteListBtn = document.getElementById('clearSiteList');
  const siteListStatus = document.getElementById('siteListStatus');
  const siteListLabel = document.getElementById('siteListLabel');
  const siteListHint = document.getElementById('siteListHint');

  const DEFAULT_SITE_LIST_STORAGE = {
    siteListMode: 'block',
    siteBlocklist: [],
    siteAllowlist: []
  };

  // Restore saved settings
  function loadSettingsIntoUI() {
    chrome.storage.local.get(
      { apiToken: '', styleMode: 'hover', ...DEFAULT_SITE_LIST_STORAGE },
      (data) => {
        apiTokenInput.value = data.apiToken || '';
        styleModeSelect.value = data.styleMode || 'hover';

        const mode = data.siteListMode || 'block';
        siteListModeSelect.value = mode;
        updateSiteListUI(mode, data);
      }
    );
  }
  loadSettingsIntoUI();

  // Keep the options page in sync with changes made from the popup.
  chrome.storage.onChanged.addListener((changes) => {
    const relevant = changes.siteListMode || changes.siteBlocklist || changes.siteAllowlist;
    if (relevant) {
      loadSettingsIntoUI();
    }
  });

  // Save API token
  function saveApiToken() {
    const token = apiTokenInput.value.trim();
    chrome.storage.local.set({ apiToken: token }, () => {
      showStatus(tokenStatus, 'Token saved.');
    });
  }

  saveTokenBtn.addEventListener('click', saveApiToken);

  // Allow saving the token by pressing Enter inside the input
  apiTokenInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      saveApiToken();
    }
  });

  // Persist style mode as soon as it changes
  styleModeSelect.addEventListener('change', (e) => {
    chrome.storage.local.set({ styleMode: e.target.value }, () => {
      showStatus(tokenStatus, ''); // avoid UI noise in appearance section
    });
  });

  // Clear recent lookups history
  clearHistoryBtn.addEventListener('click', () => {
    chrome.storage.local.set({ recent: [] }, () => {
      showStatus(clearStatus, 'History cleared.');
    });
  });

  // Delete cached reputation data
  clearCacheBtn.addEventListener('click', () => {
    if (!window.confirm('Delete all cached reputation data? This will reset icon colors back to gray on every page.')) {
      return;
    }
    chrome.storage.local.remove('reputationCache', () => {
      showStatus(cacheStatus, 'Cached IP data deleted.');
    });
  });

  // Site list mode changed: persist and swap textarea content
  siteListModeSelect.addEventListener('change', () => {
    const mode = siteListModeSelect.value;
    chrome.storage.local.get(DEFAULT_SITE_LIST_STORAGE, (data) => {
      updateSiteListUI(mode, data);
      chrome.storage.local.set({ siteListMode: mode }, () => {
        showStatus(siteListStatus, getModeStatusMessage(mode));
      });
    });
  });

  // Save the current site list
  saveSiteListBtn.addEventListener('click', () => {
    const mode = siteListModeSelect.value;
    if (mode === 'off') return;
    const key = mode === 'allow' ? 'siteAllowlist' : 'siteBlocklist';
    const raw = siteListInput.value || '';
    const list = raw
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line.length > 0);
    chrome.storage.local.set({ [key]: list }, () => {
      showStatus(siteListStatus, mode === 'allow' ? 'Allowlist saved.' : 'Blocklist saved.');
    });
  });

  // Clear the current site list
  clearSiteListBtn.addEventListener('click', () => {
    const mode = siteListModeSelect.value;
    if (mode === 'off') return;
    const listName = mode === 'allow' ? 'allowlist' : 'blocklist';
    if (!window.confirm(`Clear the entire site ${listName}?`)) {
      return;
    }
    const key = mode === 'allow' ? 'siteAllowlist' : 'siteBlocklist';
    chrome.storage.local.set({ [key]: [] }, () => {
      siteListInput.value = '';
      showStatus(siteListStatus, mode === 'allow' ? 'Allowlist cleared.' : 'Blocklist cleared.');
    });
  });

  /**
   * Updates the site list textarea label/hint and content for the selected mode.
   * @param {'off'|'block'|'allow'} mode
   * @param {Object} data
   */
  function updateSiteListUI(mode, data) {
    const isOff = mode === 'off';
    siteListInput.disabled = isOff;
    saveSiteListBtn.disabled = isOff;
    clearSiteListBtn.disabled = isOff;
    siteListLabel.classList.toggle('disabled', isOff);

    if (isOff) {
      siteListLabel.textContent = 'Sites list';
      siteListHint.textContent = 'The site list is currently turned off. Detection runs on all sites.';
      siteListInput.value = '';
      return;
    }

    if (mode === 'allow') {
      siteListLabel.textContent = 'Sites where IP detection should be enabled';
      siteListHint.textContent = 'Detection will run only on matching sites. One hostname or URL pattern per line. Use * as a wildcard at the start or end.';
      siteListInput.value = (data.siteAllowlist || []).join('\n');
    } else {
      siteListLabel.textContent = 'Sites where IP detection should be disabled';
      siteListHint.textContent = 'Detection will be disabled on matching sites. One hostname or URL pattern per line. Use * as a wildcard at the start or end. The popup and right-click lookup still work everywhere.';
      siteListInput.value = (data.siteBlocklist || []).join('\n');
    }
  }

  /**
   * Returns a short status message for a mode change.
   * @param {'off'|'block'|'allow'} mode
   * @returns {string}
   */
  function getModeStatusMessage(mode) {
    if (mode === 'off') return 'Site list turned off.';
    return mode === 'block' ? 'Blocklist mode active.' : 'Allowlist mode active.';
  }

  /**
   * Shows a short status message inside the given element.
   * @param {HTMLElement} el
   * @param {string} message
   */
  function showStatus(el, message) {
    el.textContent = message;
    if (!message) return;
    setTimeout(() => { el.textContent = ''; }, 2000);
  }
});
