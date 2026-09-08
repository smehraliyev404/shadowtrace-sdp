# ShadowTrace stub ssrfservice: a traced GET /fetch?url= that fetches the URL server-side (SSRF).
FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir \
        flask==3.0.3 \
        opentelemetry-distro==0.48b0 \
        opentelemetry-exporter-otlp==1.27.0 \
    && opentelemetry-bootstrap -a install
COPY app.py .
ENV OTEL_TRACES_EXPORTER=otlp
CMD ["opentelemetry-instrument", "python", "app.py"]
