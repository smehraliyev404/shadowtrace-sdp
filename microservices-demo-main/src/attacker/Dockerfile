# ShadowTrace attacker pod: an INSTRUMENTED gRPC client for lateral movement.
# Instrumented (not raw grpcurl) so trace context propagates and its calls to
# internal services show up as real, unprecedented edges.
FROM python:3.11-slim
WORKDIR /app

# Install the OTel stack first (it has the tightest protobuf pin), then let pip
# pick grpcio/grpcio-tools versions compatible with it rather than pinning them.
RUN pip install --no-cache-dir \
        opentelemetry-distro==0.48b0 \
        opentelemetry-exporter-otlp==1.27.0 \
        opentelemetry-instrumentation-grpc==0.48b0 \
    && pip install --no-cache-dir grpcio grpcio-tools \
    && opentelemetry-bootstrap -a install

COPY demo.proto .
# Compile the Boutique protos into Python stubs the client imports.
RUN python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. demo.proto

COPY lateral.py .

ENV OTEL_TRACES_EXPORTER=otlp
ENV OTEL_SERVICE_NAME=attacker
# Idle by default; the orchestrator drives bursts via `kubectl exec`.
CMD ["sleep", "infinity"]
