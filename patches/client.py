"""
PATCHED HttpClient: используем Safari impersonate.
Оригинал: parser/http/client.py из parser_avito v3.2.22
"""
import time
from curl_cffi import requests
from loguru import logger

from parser.cookies.base import CookiesProvider
from parser.proxies.proxy import Proxy


# ──── НАСТРОЙКИ ────
IMPERSONATE = "safari184"        # macOS Safari 18.4
# Альтернативы: "safari184_ios" (iPhone), "safari" (последняя)
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

    def _build_client(self) -> requests.Session:
        # Ключевое: impersonate="safari184" — curl_cffi сам подставит
        # правильные TLS/HTTP2 fingerprint и заголовки Safari.
        session = requests.Session(impersonate=IMPERSONATE)

        # Добавляем только те заголовки, которые не конфликтуют с impersonate.
        default_headers = {
            "accept-language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
            "referer": "https://www.avito.ru/",
        }
        session.headers.update(default_headers)

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

    def request(self, method: str, url: str, **kwargs):
        last_exc = None
        for attempt in range(1, self.max_retries + 1):
            try:
                response = self._client.request(method, url, timeout=self.timeout, **kwargs)

                if self.cookies:
                    self.cookies.update(response)

                print(response.url)
                if response.status_code in (403, 429, 439):
                    self._block_attempts += 1
                    logger.warning(
                        f"Запрос заблокирован ({response.status_code}) к {url}, "
                        f"попытка {self._block_attempts}"
                    )
                    if self._block_attempts >= self.block_threshold:
                        logger.warning("Достигнут лимит блокировок, запускается обработка")
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
