# NERD IP info

IP Detector is a Firefox extension that automatically detects **IPv4 addresses** on any web page and highlights them so you can instantly look up their reputation and metadata via the [CESNET NERD](https://nerd.cesnet.cz) API. 

The extension is built as a **Manifest V3** prototype. It is safe, self-contained, and communicates with the NERD API using a user-supplied token stored only in local browser storage.

---
## Requirements
Valid API key is required in order to use the extension. For more information visit [the official NERD website](https://nerd.cesnet.cz/)

## Features

- **Automatic IPv4 detection** on all web pages
- **Click-to-lookup** on any highlighted IP — opens the popup pre-filled with the address
- **Right-click "Search using NERD"** on any selected text on a page — opens the popup and performs a lookup automatically
- **Manual IP lookup** from the popup (enter any IPv4)
- **Traffic-light reputation scoring** based on the `rep` field
  - 🔴 Red (Score > 0.5) — Malicious
  - 🟠 Orange (Score > 0.2) — Suspicious
  - 🟢 Green (Score ≤ 0.2) — Clean / Not found
  - ⚪ Gray — Unknown 
- **Dynamic result rendering** — every field returned by the NERD API is displayed in the popup, including nested objects, dates, and arrays
- **Reverse-DNS hostname fallback** — when NERD has no data for an IP (or no hostname in its response), the popup resolves the hostname via a PTR query over DNS-over-HTTPS (Google Public DNS) and marks it as reverse-DNS sourced
- **Copy raw JSON** button to copy the full API response to the clipboard
- **One-click NERD link** to open the full IP detail page
- **Recent lookups history** stored locally (last 20 items)
- **Scan page IPs button** searches all IPs on website and shows colored icon corresponding to the reputation score 
- **Cached reputation results** 
- **Dedicated options page** for:
  - NERD API token input
  - Icon visibility selector (always visible / hover only)
  - Site blacklist/whitelist
  - Clear recent history
  - Delete cached IP data

---

## Installation

TODO

## Usage

### Page detection
- Open any page containing IPv4 addresses  
- If detection is enabled, IPs are highlighted automatically  
- Click the NERD icon next to an IP, or (in hover mode) move the cursor over the IP to reveal the icon and click it to open the popup and look it up

### Right-click lookup (context menu)
- Highlight any text on a page (for example an IP address in an article)  
- Right-click and choose **"Search using NERD"**  
- The popup opens automatically and performs the lookup  
- If the popup is already open, the lookup is run immediately without reopening  

### Popup lookup
- Type an IPv4 address into the input field and click **Lookup**  
- The result card shows the traffic-light verdict, score, tags, and every field returned by the API  
- Click **Copy raw JSON** to copy the full API response as formatted JSON to your clipboard
- Click **Open in NERD** to view the IP on the NERD website  

### Scan page IPs
- Press to perform a scan of all IPs currently rendered on page
- Each IP now has a colored icon corresponding to it's reputation score on NERD

### Settings
1. Click the **Settings** link in the popup header  
2. Paste your NERD API token and click **Save Token**
3. Choose your preferred **Icon visibility**
4. Use **Clear recent history** to erase the local lookup history

> **Security note:** The API token is stored only in storage inside your browser. It is never sent anywhere except to the official NERD API endpoint (`https://nerd.cesnet.cz`).

---

## API Details

- **Endpoint:** `GET https://nerd.cesnet.cz/nerd/api/v1/ip/{ip}`  
- **Authentication:** Raw token in the `Authorization` header (no `Bearer` prefix)  
- **Supported query types:** IPv4 only

---

## Troubleshooting

| Problem | Solution |
|---|---|
| No IPs appear on pages | Make sure detection is enabled in the popup |
| "Missing API key" error | Open Settings and paste a valid NERD API token, then click **Save Token** |
| Extension won’t load | Verify all files from this repository are present in the selected directory |
| "Request timed out" error | The API server may be slow or unreachable. Try again in a few seconds. |

---

*Version: 1.0.0*
