FROM python:3.12.15-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.lock ./
RUN pip install --no-cache-dir -r requirements.lock
COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-deps --no-cache-dir . && useradd -u 10001 -m mailsec && mkdir /data && chown mailsec:mailsec /data
USER mailsec
ENV MAILSEC_DATA_DIR=/data
CMD ["mailsec", "serve", "--host", "0.0.0.0", "--port", "8080"]
