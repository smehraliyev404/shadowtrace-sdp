# Use the official CNCF OpenTelemetry Collector Contrib image
FROM otel/opentelemetry-collector-contrib:latest

# Copy your config.yaml into the container
COPY config.yaml /etc/otelcol-contrib/config.yaml

# Expose OTLP ports (4317 gRPC, 4318 HTTP)
EXPOSE 4317 4318

# Run collector with your config
CMD ["--config=/etc/otelcol-contrib/config.yaml"]