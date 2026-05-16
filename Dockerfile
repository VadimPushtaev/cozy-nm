FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    POETRY_VERSION=2.1.4 \
    POETRY_NO_INTERACTION=1 \
    POETRY_VIRTUALENVS_CREATE=false

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl iproute2 wireguard-tools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
RUN pip install --no-cache-dir "poetry==${POETRY_VERSION}" \
    && poetry install --only main --no-root

COPY . .
RUN poetry install --only main

EXPOSE 8000
CMD ["uvicorn", "cozy_network_manager.app.main:app", "--host", "0.0.0.0", "--port", "8000"]

