FROM python:3.12-slim

WORKDIR /app

# Install Poetry and project
COPY pyproject.toml poetry.lock* ./
COPY src ./src
RUN pip install --no-cache-dir poetry \
    && poetry config virtualenvs.create false \
    && poetry install --no-dev --no-interaction
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV PYTHONPATH=/app/src
ENV PROBE_HOST=0.0.0.0
ENV PROBE_PORT=8000

EXPOSE 8000

ENTRYPOINT ["/entrypoint.sh"]
