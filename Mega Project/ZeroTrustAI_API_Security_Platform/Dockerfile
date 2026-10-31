FROM python:3.13-slim
WORKDIR /app
RUN pip install --no-cache-dir uv==0.12.19
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev
COPY common common
COPY gateway gateway
COPY demo_api demo_api
COPY dashboard dashboard
COPY ml ml
RUN useradd --create-home appuser && mkdir -p /app/data /app/ml/artifacts /app/reports && chown -R appuser:appuser /app
USER appuser
ENV PATH="/app/.venv/bin:$PATH"
EXPOSE 8000
CMD ["uvicorn", "gateway.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-proxy-headers"]
