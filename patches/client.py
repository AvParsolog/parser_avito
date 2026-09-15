"""
PATCHED HttpClient: curl_cffi + Playwright fallback для Avito.
Оригинал: parser/http/client.py из parser_avito v3.2.22
"""
import time
import asyncio
from curl_cffi import requests
from loguru import logger

from parser.cookies.base import CookiesProvider
from parser.proxies.proxy import Proxy

# ──── НАСТРОЙКИ ────
IMPERSONATE = "firefox135"          # основной быстрый клиент
PLAYWRIGHT_TIMEOUT = 60_000         # 60 секунд для браузера
PLAYWRIGHT_HEADLESS = True
# ───────────────────


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
    #  PLAYWRIGHT FALLBACK
    # ──────────────────────────────────────────────
    async def _playwright_fetch(self, url: str) -> str:
        """Загружает страницу через реальный браузер (Playwright)."""
        from playwright.async_api import async_playwright
        from playwright_stealth import Stealth

        proxy_str = self.proxy.get_httpx_proxy()

        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=PLAYWRIGHT_HEADLESS,
                args=[
                    "--no-sandbox",
                    "--disable-blink-features=AutomationControlled",
                    "--disable-dev-shm-usage",
                ],
            )

            context_args = {
                "user_agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/140.0.0.0 Safari/537.36"
                ),
                "viewport": {"width": 1920, "height": 1080},
                "locale": "ru-RU",
            }

            if proxy_str:
                context_args["proxy"] = {"server": proxy_str}

            context = await browser.new_context(**context_args)
            page = await context.new_page()

            # Применяем stealth, чтобы скрыть webdriver
            stealth = Stealth()
            await stealth.apply_stealth_async(page)

            # Загружаем cookies из нашего провайдера
            if self.cookies:
                try:
                    await context.add_cookies([
                        {"name": k, "value": v, "domain": ".avito.ru", "path": "/"}
                        for k, v in self.cookies.get().items()
                    ])
                except Exception as err:
                    logger.warning(f"Playwright: не удалось добавить cookies: {err}")

            logger.info(f"🎭 Playwright загружает: {url}")
            await page.goto(url, wait_until="domcontentloaded", timeout=PLAYWRIGHT_TIMEOUT)

            # Ждём немного, чтобы прошли возможные JS-челленджи
            await asyncio.sleep(3)

            # Забираем cookies обратно (Avito мог их обновить)
            if self.cookies:
                try:
                    playwright_cookies = await context.cookies()
                    new_cookies = {c["name"]: c["value"] for c in playwright_cookies}
                    # Можно добавить логику сохранения обратно в CookiesProvider
                    logger.debug(f"Playwright получил {len(new_cookies)} cookies")
                except Exception:
                    pass

            html = await page.content()
            await browser.close()
            return html

    def _playwright_fallback(self, url: str) -> str:
        """Синхронная обёртка для вызова Playwright из sync-кода."""
        logger.info(f"🔄 Fallback на Playwright для: {url}")
        try:
            # Запускаем async-функцию в отдельном event loop
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
                # 1. Пробуем быстрый curl_cffi
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

                        # 2. Пробуем Playwright
                        try:
                            html = self._playwright_fallback(url)
                            # Возвращаем объект-заглушку, совместимый с response
                            return _FakeResponse(html, 200, url)
                        except Exception as pw_err:
                            logger.error(f"Playwright тоже не помог: {pw_err}")

                        # 3. Если Playwright не помог — старая логика
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
