"""
PATCHED HttpClient: curl_cffi (Safari iOS) + Playwright WebKit (нативный Safari).
Оригинал: parser/http/client.py из parser_avito v3.2.22
"""
import time
import asyncio
from curl_cffi import requests
from loguru import logger

from parser.cookies.base import CookiesProvider
from parser.proxies.proxy import Proxy

# ──── НАСТРОЙКИ curl_cffi ────
IMPERSONATE = "safari184_ios"     # Safari 18.4 для iOS
# ─────────────────────────────

# ──── НАСТРОЙКИ Playwright ────
PLAYWRIGHT_TIMEOUT = 60_000
PLAYWRIGHT_HEADLESS = True
PLAYWRIGHT_DEVICE = "iPhone 15"    # профиль Safari из реестра Playwright
PLAYWRIGHT_ENGINE = "webkit"       # "webkit" (нативный Safari) или "chromium" (fallback)
# ─────────────────────────────


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
        self._client = self._build_client()

    # ──────────────────────────────────────────────
    #  БЫСТРЫЙ КЛИЕНТ (curl_cffi)
    # ──────────────────────────────────────────────
    def _build_client(self) -> requests.Session:
        session = requests.Session(impersonate=IMPERSONATE)
        session.headers.update({
            "accept-language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
            "referer": "https://www.avito.ru/",
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
    #  PLAYWRIGHT FALLBACK (WebKit / Safari)
    # ──────────────────────────────────────────────
    async def _playwright_fetch(self, url: str) -> str:
        """
        Грузим HTML-страницу Avito (для прогрева сессии),
        затем из её контекста делаем fetch к API.
        Движок: WebKit (нативный Safari) с fallback на Chromium.
        """
        from playwright.async_api import async_playwright, devices

        proxy_str = self.proxy.get_httpx_proxy()

        async with async_playwright() as p:
            # ─── Выбираем движок ───
            browser = None
            engine_used = None

            if PLAYWRIGHT_ENGINE == "webkit":
                try:
                    logger.info("🍎 Запускаю WebKit (нативный Safari)")
                    browser = await p.webkit.launch(headless=PLAYWRIGHT_HEADLESS)
                    engine_used = "webkit"
                except Exception as err:
                    logger.warning(f"WebKit не запустился ({err}), переключаюсь на Chromium")

            if browser is None:
                logger.info("🌐 Запускаю Chromium (Safari-emulation)")
                browser = await p.chromium.launch(
                    headless=PLAYWRIGHT_HEADLESS,
                    args=[
                        "--no-sandbox",
                        "--disable-blink-features=AutomationControlled",
                        "--disable-dev-shm-usage",
                    ],
                )
                engine_used = "chromium"

            logger.info(f"✅ Движок: {engine_used}")

            # Берём профиль Safari-устройства (iPhone) из реестра Playwright.
            safari_device = devices[PLAYWRIGHT_DEVICE]

            context_args = {
                **safari_device,
                "locale": "ru-RU",
                "timezone_id": "Europe/Moscow",
            }
            if proxy_str:
                context_args["proxy"] = {"server": proxy_str}

            context = await browser.new_context(**context_args)
            page = await context.new_page()

            # Анти-детект: скрываем webdriver и chrome-объекты.
            # Для WebKit это тоже актуально, хоть и в меньшей степени.
            await page.add_init_script("""
                Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
                Object.defineProperty(navigator, 'platform', { get: () => 'iPhone' });
                Object.defineProperty(navigator, 'vendor', { get: () => 'Apple Computer, Inc.' });
                Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });
                Object.defineProperty(navigator, 'languages', { get: () => ['ru-RU', 'ru', 'en-US', 'en'] });
            """)

            # ─── ШАГ 1: прогрев на главной ───
            logger.info("🎭 Playwright: открываю главную для прогрева сессии")
            try:
                await page.goto(
                    "https://www.avito.ru/",
                    wait_until="domcontentloaded",
                    timeout=PLAYWRIGHT_TIMEOUT,
                )
            except Exception as err:
                logger.warning(f"Не удалось открыть главную: {err}")

            await asyncio.sleep(3)

            # ─── ШАГ 2: fetch к API из контекста страницы ───
            logger.info(f"🎭 Playwright: fetch к {url}")
            try:
                result_text = await page.evaluate(
                    """
                    async (apiUrl) => {
                        const resp = await fetch(apiUrl, {
                            method: 'GET',
                            credentials: 'include',
                            headers: {
                                'Accept': 'application/json, text/plain, */*',
                                'X-Requested-With': 'XMLHttpRequest',
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
                        f"Playwright получил НЕ JSON (первые 200 символов): {body[:200]!r}"
                    )

                # ─── ШАГ 3: забираем cookies обратно ───
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
        """Синхронная обёртка для вызова Playwright из sync-кода."""
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
    #  ОСНОВНОЙ МЕТОД
    # ──────────────────────────────────────────────
    def request(self, method: str, url: str, **kwargs):
        last_exc = None

        for attempt in range(1, self.max_retries + 1):
            try:
                response = self._client.request(method, url, timeout=self.timeout, **kwargs)

                if self.cookies:
                    self.cookies.update(response)

                if response.status_code in (403, 429, 439):
                    self._block_attempts += 1
                    logger.warning(
                        f"Запрос заблокирован ({response.status_code}) к {url}, "
                        f"попытка {self._block_attempts}"
                    )

                    if self._block_attempts >= self.block_threshold:
                        logger.warning("Достигнут лимит блокировок, запускается обработка")

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

                    time.sleep(self.retry_delay)
                    continue

                self._block_attempts = 0
                response.raise_for_status()
                return response

            except requests.RequestsError as e:
                last_exc = e
                self._block_attempts = 0
                logger.warning(f"Request error (attempt {attempt}): {e}")
                time.sleep(self.retry_delay)

        raise RuntimeError("HTTP запросы были неуспешными") from last_exc


class _FakeResponse:
    """Минимальная заглушка response для совместимости с parser_cls.py."""
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
