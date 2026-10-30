FROM python:3.12-slim
WORKDIR /app
COPY requirements.lock .
RUN pip install --no-cache-dir -r requirements.lock
COPY platform_api ./platform_api
EXPOSE 8090
CMD ["uvicorn", "platform_api.app:app", "--host", "0.0.0.0", "--port", "8090"]
