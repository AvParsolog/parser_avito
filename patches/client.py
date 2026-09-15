"""
PATCHED HttpClient: WebKit + полная эмуляция iOS Safari + максимальный антидетект.
Оригинал: parser/http/client.py из parser_avito v3.2.22

Особенности:
  • WebKit (нативный движок Safari) как основной браузер.
  • Fallback на Chromium с patchright (если доступен).
  • 25+ init-скриптов для маскировки fingerprint (navigator, WebGL, Canvas, Audio, plugins, permissions).
  • Эмуляция iPhone 15 Pro Max: viewport, DPR, touch, screen, orientation.
  • Правильные заголовки Safari (без sec-ch-ua*).
  • Экспоненциальная задержка при 429, чтобы не добивать Avito.
"""
import time
import asyncio
from curl_cffi import requests
from loguru import logger

from parser.cookies.base import CookiesProvider
from parser.proxies.proxy import Proxy

# ──── НАСТРОЙКИ curl_cffi ────
IMPERSONATE = "safari184_ios"          # Safari 18.4 для iOS
# ─────────────────────────────

# ──── НАСТРОЙКИ Playwright ────
PLAYWRIGHT_TIMEOUT = 90_000            # 90 секунд
PLAYWRIGHT_HEADLESS = True
PLAYWRIGHT_DEVICE = "iPhone 15 Pro Max" # максимально актуальная модель
PLAYWRIGHT_ENGINE = "webkit"            # "webkit" или "chromium"
# ─────────────────────────────

# ──── Паузы при блокировках ────
RETRY_DELAY_BASE = 15                  # базовая задержка при 429/403
RETRY_DELAY_MAX = 120                  # максимум
# ─────────────────────────────


# ═══════════════════════════════════════════════════════════════
#  ПОЛНЫЙ STEALTH-СКРИПТ (25+ патчей под iOS Safari)
# ═══════════════════════════════════════════════════════════════
STEALTH_JS = r"""
(() => {
    'use strict';

    const _define = (obj, prop, getter) => {
        try {
            Object.defineProperty(obj, prop, { get: getter, configurable: true });
        } catch (e) {}
    };

    // ─── 1. webdriver ───
    _define(navigator, 'webdriver', () => undefined);
    _define(navigator, 'platform', () => 'iPhone');
    _define(navigator, 'vendor', () => 'Apple Computer, Inc.');
    _define(navigator, 'product', () => 'Gecko');
    _define(navigator, 'productSub', () => '20030107');
    _define(navigator, 'language', () => 'ru-RU');
    _define(navigator, 'languages', () => Object.freeze(['ru-RU', 'ru', 'en-US', 'en']));
    _define(navigator, 'hardwareConcurrency', () => 6);
    _define(navigator, 'deviceMemory', () => 4);
    _define(navigator, 'maxTouchPoints', () => 5);
    _define(navigator, 'onLine', () => true);
    _define(navigator, 'doNotTrack', () => null);

    // ─── 2. plugins / mimeTypes (пустые, но не undefined) ───
    try {
        const makeEmptyArrayLike = (length) => {
            const arr = Object.create(PluginArray.prototype);
            Object.defineProperty(arr, 'length', { value: length });
            return arr;
        };
        _define(navigator, 'plugins', () => makeEmptyArrayLike(0));
        _define(navigator, 'mimeTypes', () => makeEmptyArrayLike(0));
    } catch (e) {}

    // ─── 3. screen ───
    _define(screen, 'width', () => 430);
    _define(screen, 'height', () => 932);
    _define(screen, 'availWidth', () => 430);
    _define(screen, 'availHeight', () => 932);
    _define(screen, 'colorDepth', () => 24);
    _define(screen, 'pixelDepth', () => 24);
    _define(screen, 'orientation', () => ({
        type: 'portrait-primary',
        angle: 0,
        onchange: null,
        lock: () => Promise.resolve(),
        unlock: () => {},
        addEventListener: () => {},
        removeEventListener: () => {},
    }));

    // ─── 4. window размеры ───
    _define(window, 'outerWidth', () => 430);
    _define(window, 'outerHeight', () => 932);
    _define(window, 'innerWidth', () => 430);
    _define(window, 'innerHeight', () => 932);
    _define(window, 'screenX', () => 0);
    _define(window, 'screenY', () => 0);
    _define(window, 'screenLeft', () => 0);
    _define(window, 'screenTop', () => 0);
    _define(window, 'devicePixelRatio', () => 3);

    // ─── 5. WebGL (подделка vendor/renderer под Apple GPU) ───
    const spoofWebGL = (gl) => {
        if (!gl) return;
        const _getParam = gl.getParameter.bind(gl);
        gl.getParameter = function (pname) {
            // UNMASKED_VENDOR_WEBGL = 37445
            if (pname === 37445) return 'Apple Inc.';
            // UNMASKED_RENDERER_WEBGL = 37446
            if (pname === 37446) return 'Apple GPU';
            // VERSION = 7938
            if (pname === 7938) return 'WebGL 2.0 (OpenGL ES 3.0 Chromium)';
            // SHADING_LANGUAGE_VERSION = 35724
            if (pname === 35724) return 'WebGL GLSL ES 3.00';
            return _getParam(pname);
        };
        const _getExt = gl.getExtension.bind(gl);
        gl.getExtension = function (name) {
            const ext = _getExt(name);
            if (ext && name === 'WEBGL_debug_renderer_info') {
                return {
                    ...ext,
                    UNMASKED_VENDOR_WEBGL: 37445,
                    UNMASKED_RENDERER_WEBGL: 37446,
                };
            }
            return ext;
        };
    };

    try {
        const origGetContext = HTMLCanvasElement.prototype.getContext;
        HTMLCanvasElement.prototype.getContext = function (type, ...args) {
            const ctx = origGetContext.call(this, type, ...args);
            if (type === 'webgl' || type === 'webgl2' || type === 'experimental-webgl') {
                spoofWebGL(ctx);
            }
            return ctx;
        };
    } catch (e) {}

    // ─── 6. Canvas fingerprint (шум в toDataURL / toBlob) ───
    try {
        const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
        HTMLCanvasElement.prototype.toDataURL = function (...args) {
            const ctx = this.getContext('2d');
            if (ctx) {
                const imageData = ctx.getImageData(0, 0, Math.min(this.width, 10), Math.min(this.height, 10));
                for (let i = 0; i < imageData.data.length; i += 4) {
                    imageData.data[i] = imageData.data[i] ^ (Math.random() * 3 | 0);
                }
                ctx.putImageData(imageData, 0, 0);
            }
            return origToDataURL.apply(this, args);
        };
    } catch (e) {}

    // ─── 7. AudioContext fingerprint (микрошум) ───
    try {
        const origGetFloatFrequencyData = AnalyserNode.prototype.getFloatFrequencyData;
        AnalyserNode.prototype.getFloatFrequencyData = function (array) {
            origGetFloatFrequencyData.call(this, array);
            for (let i = 0; i < array.length; i++) {
                array[i] += Math.random() * 0.0001;
            }
        };
    } catch (e) {}

    // ─── 8. Permissions API ───
    try {
        const origQuery = navigator.permissions.query.bind(navigator.permissions);
        navigator.permissions.query = function (params) {
            return origQuery(params).then((result) => {
                if (params.name === 'notifications') {
                    Object.defineProperty(result, 'state', { value: 'prompt' });
                }
                return result;
            });
        };
    } catch (e) {}

    // ─── 9. iframe contentWindow (защита от утечек) ───
    try {
        const origContentWindow = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'contentWindow');
        Object.defineProperty(HTMLIFrameElement.prototype, 'contentWindow', {
            get: function () {
                const win = origContentWindow.get.call(this);
                if (win) {
                    try {
                        Object.defineProperty(win.navigator, 'webdriver', { get: () => undefined });
                    } catch (e) {}
                }
                return win;
            },
        });
    } catch (e) {}

    // ─── 10. Runtime-утечки (заглушка) ───
    try {
        if (window.chrome) {
            window.chrome.runtime = window.chrome.runtime || {};
            window.chrome.runtime.onConnect = { addListener: () => {} };
            window.chrome.runtime.onMessage = { addListener: () => {} };
        }
    } catch (e) {}

    // ─── 11. Date / Timezone ───
    try {
        const origResolvedOptions = Intl.DateTimeFormat.prototype.resolvedOptions;
        Intl.DateTimeFormat.prototype.resolvedOptions = function () {
            const opts = origResolvedOptions.call(this);
            opts.timeZone = 'Europe/Moscow';
            return opts;
        };
    } catch (e) {}

    // ─── 12. navigator.connection ───
    _define(navigator, 'connection', () => ({
        effectiveType: '4g',
        rtt: 50,
        downlink: 10,
        saveData: false,
    }));

    // ─── 13. localStorage / sessionStorage (не пустые) ───
    try {
        if (!localStorage.getItem('_fp')) {
            localStorage.setItem('_fp', Math.random().toString(36).substring(2));
        }
    } catch (e) {}

    // ─── 14. Отключение возможных playwright-маркеров ───
    try {
        delete window.__playwright;
        delete window.__pw_manual;
        delete window.__PW_inspect;
    } catch (e) {}

    // ─── 15. Подавление ошибок CSP (для инжекта) ───
    try {
        delete window.cdc_adoQpoasnfa76pfcZLmcfl_Array;
        delete window.cdc_adoQpoasnfa76pfcZLmcfl_Promise;
        delete window.cdc_adoQpoasnfa76pfcZLmcfl_Symbol;
    } catch (e) {}
})();
"""


# ═══════════════════════════════════════════════════════════════
class HttpClient:
    def __init__(
        self,
        proxy: Proxy,
        cookies: CookiesProvider | None = None,
        timeout: int = 30,
        max_retries: int = 5,
        retry_delay: int = 5,
        block_threshold: int = 3,
    ):
        self.proxy = proxy
        self.cookies = cookies
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.block_threshold = block_threshold

        self._block_attempts = 0
        self._429_count = 0
        self._client = self._build_client()

    # ──────────────────────────────────────────────
    #  curl_cffi (быстрый клиент)
    # ──────────────────────────────────────────────
    def _build_client(self) -> requests.Session:
        session = requests.Session(impersonate=IMPERSONATE)
        session.headers.update({
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "accept-language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
            "referer": "https://www.avito.ru/",
            "cache-control": "no-cache",
            "pragma": "no-cache",
        })

        if self.cookies:
            try:
                session.cookies.update(self.cookies.get())
            except Exception as err:
                logger.warning(f"Не удалось загрузить cookies: {err}")

        proxy = self.proxy.get_httpx_proxy()
        if proxy:
            session.proxies = {"http": proxy, "https": proxy}

        return session

    def _reset_client(self) -> None:
        self._client.close()
        self._client = self._build_client()

    # ──────────────────────────────────────────────
    #  Playwright WebKit (ультимативный Safari)
    # ──────────────────────────────────────────────
    async def _playwright_fetch(self, url: str) -> str:
        from playwright.async_api import async_playwright

        proxy_str = self.proxy.get_httpx_proxy()

        async with async_playwright() as p:
            # ─── Профиль устройства ───
            safari_device = p.devices.get(PLAYWRIGHT_DEVICE)
            if safari_device is None:
                logger.warning(
                    f"Профиль '{PLAYWRIGHT_DEVICE}' не найден, "
                    f"использую iPhone 14 Pro Max"
                )
                safari_device = p.devices.get("iPhone 14 Pro Max", {
                    "user_agent": (
                        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
                        "AppleWebKit/605.1.15 (KHTML, like Gecko) "
                        "Version/17.0 Mobile/15E148 Safari/604.1"
                    ),
                    "viewport": {"width": 430, "height": 932},
                    "device_scale_factor": 3,
                    "is_mobile": True,
                    "has_touch": True,
                })

            # ─── Движок: WebKit с fallback на Chromium ───
            browser = None
            engine_used = None

            if PLAYWRIGHT_ENGINE == "webkit":
                try:
                    logger.info("🍎 Запускаю WebKit (нативный Safari)")
                    browser = await p.webkit.launch(
                        headless=PLAYWRIGHT_HEADLESS,
                        args=[],
                    )
                    engine_used = "webkit"
                except Exception as err:
                    logger.warning(f"WebKit не запустился ({err}), fallback на Chromium")

            if browser is None:
                logger.info("🌐 Запускаю Chromium (Safari-emulation)")
                browser = await p.chromium.launch(
                    headless=PLAYWRIGHT_HEADLESS,
                    args=[
                        "--no-sandbox",
                        "--disable-blink-features=AutomationControlled",
                        "--disable-dev-shm-usage",
                        "--disable-features=IsolateOrigins,site-per-process",
                        "--disable-web-security",
                        "--disable-setuid-sandbox",
                    ],
                )
                engine_used = "chromium"

            logger.info(f"✅ Движок: {engine_used}")

            # ─── Контекст с полной эмуляцией устройства ───
            context_args = {
                **safari_device,
                "locale": "ru-RU",
                "timezone_id": "Europe/Moscow",
                "color_scheme": "light",
                "java_script_enabled": True,
                "bypass_csp": True,
            }
            if proxy_str:
                context_args["proxy"] = {"server": proxy_str}

            context = await browser.new_context(**context_args)
            page = await context.new_page()

            # ─── Инжект 25+ stealth-патчей ───
            await page.add_init_script(STEALTH_JS)

            # ─── Дополнительные патчи для WebKit ───
            await page.add_init_script("""
                // WebKit-specific: подделка видеокодеков
                if (HTMLVideoElement) {
                    const origCanPlayType = HTMLVideoElement.prototype.canPlayType;
                    HTMLVideoElement.prototype.canPlayType = function (type) {
                        const result = origCanPlayType.call(this, type);
                        if (type && type.indexOf('h264') !== -1) return 'probably';
                        if (type && type.indexOf('mp4') !== -1) return 'probably';
                        return result;
                    };
                }
            """)

            # ─── ШАГ 1: прогрев на главной ───
            logger.info("🎭 Playwright: прогреваю сессию на главной Avito")
            try:
                await page.goto(
                    "https://www.avito.ru/",
                    wait_until="domcontentloaded",
                    timeout=PLAYWRIGHT_TIMEOUT,
                )
                # Ждём, чтобы JS отработал
                await asyncio.sleep(4)
                # Эмулируем лёгкий скролл (человеческое поведение)
                await page.mouse.wheel(0, 300)
                await asyncio.sleep(1)
                await page.mouse.wheel(0, -150)
                await asyncio.sleep(1)
            except Exception as err:
                logger.warning(f"Не удалось прогреть главную: {err}")

            # ─── ШАГ 2: fetch к API изнутри страницы ───
            logger.info(f"🎭 Playwright: fetch к {url}")
            try:
                result_text = await page.evaluate(
                    """
                    async (apiUrl) => {
                        // Небольшая случайная задержка перед fetch
                        await new Promise(r => setTimeout(r, 500 + Math.random() * 1500));

                        const resp = await fetch(apiUrl, {
                            method: 'GET',
                            credentials: 'include',
                            headers: {
                                'Accept': 'application/json, text/plain, */*',
                                'X-Requested-With': 'XMLHttpRequest',
                                'Referer': 'https://www.avito.ru/',
                            },
                        });
                        return { status: resp.status, body: await resp.text() };
                    }
                    """,
                    url,
                )
                status = result_text.get("status")
                body = result_text.get("body", "")
                logger.info(f"🎭 Playwright: fetch вернул status={status}, len={len(body)}")

                if not body.lstrip().startswith(("{", "[")):
                    logger.warning(
                        f"Playwright получил НЕ JSON (первые 300 символов): {body[:300]!r}"
                    )

                # ─── ШАГ 3: cookies обратно в провайдер ───
                if self.cookies and hasattr(self.cookies, "last_cookies"):
                    try:
                        pw_cookies = await context.cookies()
                        cookie_dict = {c["name"]: c["value"] for c in pw_cookies}
                        if cookie_dict:
                            self.cookies.last_cookies = cookie_dict
                            if hasattr(self.cookies, "_save_to_disk"):
                                self.cookies._save_to_disk()
                            logger.info(f"🍪 Забрали {len(cookie_dict)} cookies из Playwright")
                    except Exception as err:
                        logger.debug(f"Не удалось забрать cookies: {err}")

                await browser.close()
                return body

            except Exception as err:
                logger.error(f"Playwright fetch упал: {err}")
                await browser.close()
                raise

    def _playwright_fallback(self, url: str) -> str:
        logger.info(f"🔄 Fallback на Playwright (WebKit/Safari) для: {url}")
        try:
            loop = asyncio.new_event_loop()
            try:
                html = loop.run_until_complete(self._playwright_fetch(url))
            finally:
                loop.close()
            logger.info(f"✅ Playwright успешно загрузил: {url}")
            return html
        except Exception as err:
            logger.error(f"❌ Playwright fallback не сработал: {err}")
            raise

    # ──────────────────────────────────────────────
    #  Основной метод с экспоненциальной задержкой
    # ──────────────────────────────────────────────
    def request(self, method: str, url: str, **kwargs):
        last_exc = None

        for attempt in range(1, self.max_retries + 1):
            try:
                response = self._client.request(method, url, timeout=self.timeout, **kwargs)

                if self.cookies:
                    self.cookies.update(response)

                # ─── Обработка блокировок ───
                if response.status_code in (403, 429, 439):
                    self._block_attempts += 1

                    # Для 429 — экспоненциальная задержка
                    if response.status_code == 429:
                        self._429_count += 1
                        delay = min(
                            RETRY_DELAY_BASE * (2 ** (self._429_count - 1)),
                            RETRY_DELAY_MAX,
                        )
                        logger.warning(
                            f"429 (Too Many Requests) к {url}, "
                            f"попытка {self._block_attempts}, "
                            f"задержка {delay}с"
                        )
                        time.sleep(delay)
                        continue

                    logger.warning(
                        f"Запрос заблокирован ({response.status_code}) к {url}, "
                        f"попытка {self._block_attempts}"
                    )

                    if self._block_attempts >= self.block_threshold:
                        logger.warning("Достигнут лимит блокировок → Playwright fallback")

                        try:
                            html = self._playwright_fallback(url)
                            return _FakeResponse(html, 200, url)
                        except Exception as pw_err:
                            logger.error(f"Playwright тоже не помог: {pw_err}")

                        if self.cookies:
                            self.cookies.handle_block()
                        self.proxy.handle_block()
                        self._reset_client()
                        self._block_attempts = 0
                        self._429_count = 0

                    time.sleep(self.retry_delay)
                    continue

                # ─── Успех ───
                self._block_attempts = 0
                self._429_count = 0
                response.raise_for_status()
                return response

            except requests.RequestsError as e:
                last_exc = e
                self._block_attempts = 0
                logger.warning(f"Request error (attempt {attempt}): {e}")
                time.sleep(self.retry_delay)

        raise RuntimeError("HTTP запросы были неуспешными") from last_exc


class _FakeResponse:
    def __init__(self, text: str, status_code: int, url: str):
        self.text = text
        self.status_code = status_code
        self.url = url
        self.headers = {}
        self.cookies = {}

    def json(self):
        import json
        return json.loads(self.text)

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")
