FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app/src
ENV PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml README.md requirements-dev.txt ./
RUN python -m pip install --upgrade pip \
    && python -m pip install -r requirements-dev.txt

COPY src ./src
COPY scripts ./scripts
COPY tests ./tests
COPY config ./config
COPY data/sample ./data/sample

CMD ["python", "-m", "pytest"]
