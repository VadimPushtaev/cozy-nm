FROM docker:27.5.1-cli AS docker-cli

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    POETRY_VERSION=2.1.4 \
    POETRY_NO_INTERACTION=1 \
    POETRY_VIRTUALENVS_CREATE=false

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl iproute2 iputils-ping wireguard-tools \
    && rm -rf /var/lib/apt/lists/*

COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=docker-cli /usr/local/libexec/docker/cli-plugins /usr/local/libexec/docker/cli-plugins

WORKDIR /app
COPY pyproject.toml poetry.lock README.md ./
RUN pip install --no-cache-dir "poetry==${POETRY_VERSION}" \
    && poetry install --only main --no-root

COPY . .
RUN poetry install --only main

EXPOSE 8000
CMD ["uvicorn", "cozy_network_manager.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
