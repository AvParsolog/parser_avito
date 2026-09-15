FROM mcr.microsoft.com/playwright/python:v1.55.0-noble
LABEL org.opencontainers.image.source=https://github.com/avparsolog/parser_avito

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --upgrade pip && pip install -r requirements.txt

# Обновляем браузеры под версию playwright из requirements.txt.
# В этом образе уже есть все системные зависимости для Chromium и WebKit.
RUN python -m playwright install chromium-headless-shell webkit

COPY . /app
COPY entrypoint.sh /

ENTRYPOINT ["/bin/bash", "/entrypoint.sh"]
