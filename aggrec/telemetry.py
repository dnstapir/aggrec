import logging

from fastapi import FastAPI
from opentelemetry import metrics, trace
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.botocore import BotocoreInstrumentor
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.pymongo import PymongoInstrumentor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import ConsoleMetricExporter, PeriodicExportingMetricReader
from opentelemetry.sdk.resources import SERVICE_NAME, Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter

logger = logging.getLogger(__name__)


def configure_opentelemetry(
    app: FastAPI,
    service_name: str,
    spans_endpoint: str | None = None,
    metrics_endpoint: str | None = None,
    insecure: bool = True,
) -> None:
    resource = Resource(attributes={SERVICE_NAME: service_name})

    traceProvider = TracerProvider(resource=resource)

    processor = BatchSpanProcessor(
        OTLPSpanExporter(endpoint=spans_endpoint, insecure=insecure) if spans_endpoint else ConsoleSpanExporter()
    )
    traceProvider.add_span_processor(processor)
    trace.set_tracer_provider(traceProvider)
    logger.debug("OTLP spans via %s", spans_endpoint or "console")

    reader = PeriodicExportingMetricReader(
        OTLPMetricExporter(endpoint=metrics_endpoint, insecure=insecure)
        if metrics_endpoint
        else ConsoleMetricExporter()
    )
    meterProvider = MeterProvider(resource=resource, metric_readers=[reader])
    metrics.set_meter_provider(meterProvider)
    logger.debug("OTLP metrics via %s", metrics_endpoint or "console")

    FastAPIInstrumentor.instrument_app(
        app=app,
        http_capture_headers_server_request=[
            "x-request-id",
            "traceparent",
            "tracestate",
        ],
    )
    PymongoInstrumentor().instrument()
    BotocoreInstrumentor().instrument()

    logger.info("OpenTelemetry configured")
