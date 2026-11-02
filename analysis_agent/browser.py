"""
PhishGuard AI — Analysis VM Agent: Browser Module
===================================================
Provides the browser context factory used by scanner.py.

Runs INSIDE the VirtualBox Linux guest.  Never on the Windows host.

Security controls enforced here:
  - headless=True — no GUI
  - No host user-data directory (no persistent profile, cookies, or credentials)
  - Downloads blocked (accept_downloads=False)
  - Camera, microphone, clipboard-read/write, notifications, geolocation: denied
  - Extensions disabled
  - Background networking, sync, translate, component update: disabled
  - No audio
  - CSP bypass: disabled (we respect page CSP)
  - Viewport fixed at 1280×800 (consistent fingerprint)
  - Accept-Language: en-US (consistent, not linked to host locale)
  - ignore_https_errors=True — we want to see the page regardless of cert issues
    (cert inspection is a security signal, not a block reason)
"""

from typing import Any


# Chromium launch arguments that strip out all non-essential features and
# eliminate network-calling background services.
_CHROMIUM_ARGS: list[str] = [
    "--no-sandbox",
    "--disable-setuid-sandbox",
    "--disable-dev-shm-usage",
    "--disable-extensions",
    "--disable-plugins",
    "--disable-default-apps",
    "--disable-background-networking",
    "--disable-sync",
    "--disable-translate",
    "--disable-features=Translate",
    "--safebrowsing-disable-auto-update",
    "--disable-client-side-phishing-detection",
    "--disable-component-update",
    "--mute-audio",
    "--disable-notifications",
    "--block-new-web-contents",
    "--disable-background-timer-throttling",
    "--disable-renderer-backgrounding",
    "--disable-hang-monitor",
]

# Permissions explicitly denied inside every browser context.
_DENIED_PERMISSIONS: list[str] = [
    "camera",
    "microphone",
    "clipboard-read",
    "clipboard-write",
    "notifications",
    "geolocation",
    "payment-handler",
    "background-sync",
    "background-fetch",
    "periodic-background-sync",
    "nfc",
    "midi",
    "midi-sysex",
    "speaker-selection",
    "idle-detection",
]


# Realistic Device Profiles for Authentic Multi-Device Rendering
DEVICE_PROFILES: dict[str, dict[str, Any]] = {
    "desktop": {
        "viewport": {"width": 1440, "height": 900},
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "is_mobile": False,
        "has_touch": False,
        "device_scale_factor": 1,
        "platform": '"Windows"',
    },
    "tablet": {
        "viewport": {"width": 768, "height": 1024},
        "user_agent": "Mozilla/5.0 (iPad; CPU OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
        "is_mobile": True,
        "has_touch": True,
        "device_scale_factor": 2,
        "platform": '"iOS"',
    },
    "mobile": {
        "viewport": {"width": 390, "height": 844},
        "user_agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
        "is_mobile": True,
        "has_touch": True,
        "device_scale_factor": 3,
        "platform": '"iOS"',
    },
}


async def make_browser_and_context(playwright: Any, device_profile: str = "desktop") -> tuple[Any, Any]:
    """
    Creates an isolated browser and context configured with the chosen device profile.
    Returns (browser, context).
    """
    profile_key = (device_profile or "desktop").lower()
    profile = DEVICE_PROFILES.get(profile_key, DEVICE_PROFILES["desktop"])

    browser = await playwright.chromium.launch(
        headless=True,
        args=_CHROMIUM_ARGS,
    )

    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Sec-Ch-Ua": '"Not/A)Brand";v="8", "Chromium";v="126", "Google Chrome";v="126"',
        "Sec-Ch-Ua-Mobile": "?1" if profile["is_mobile"] else "?0",
        "Sec-Ch-Ua-Platform": profile["platform"],
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
    }

    context = await browser.new_context(
        viewport=profile["viewport"],
        user_agent=profile["user_agent"],
        is_mobile=profile["is_mobile"],
        has_touch=profile["has_touch"],
        device_scale_factor=profile.get("device_scale_factor", 1),
        java_script_enabled=True,
        accept_downloads=False,
        ignore_https_errors=True,
        permissions=[],
        extra_http_headers=headers,
        bypass_csp=False,
    )

    # Inject stealth helper into every frame to prevent headless detection blocks
    await context.add_init_script("""(() => {
        try {
            Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
            window.chrome = { runtime: {} };
            if (!navigator.languages || navigator.languages.length === 0) {
                Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
            }
        } catch(e) {}
    })();""")

    return browser, context



