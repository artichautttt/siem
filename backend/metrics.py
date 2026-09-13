"""
metrics.py — Instrumentation Prometheus du backend Flask.

Expose /metrics au format Prometheus (texte). Trois métriques :
- http_requests_total{method,endpoint,status} : compteur de requêtes HTTP
- http_request_duration_seconds{method,endpoint} : histogramme de latence
- alerts_generated_total{rule_name,severity} : compteur d'alertes produites
  par le moteur de détection (detector.py), incrémenté à chaque exécution
  de POST /api/detect.
"""
import time

from flask import request
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST

HTTP_REQUESTS_TOTAL = Counter(
    "http_requests_total",
    "Nombre total de requêtes HTTP reçues",
    ["method", "endpoint", "status"],
)

HTTP_REQUEST_DURATION_SECONDS = Histogram(
    "http_request_duration_seconds",
    "Durée des requêtes HTTP (secondes)",
    ["method", "endpoint"],
)

ALERTS_GENERATED_TOTAL = Counter(
    "alerts_generated_total",
    "Nombre total d'alertes générées par le moteur de détection",
    ["rule_name", "severity"],
)


def init_metrics(app):
    """Enregistre les hooks before/after_request et l'endpoint /metrics."""

    @app.before_request
    def _start_timer():
        request._metrics_start = time.perf_counter()

    @app.after_request
    def _record_metrics(response):
        # request.url_rule est None pour les routes inconnues (404) : on
        # retombe alors sur request.path pour ne pas perdre la métrique.
        endpoint = request.url_rule.rule if request.url_rule else request.path
        duration = time.perf_counter() - getattr(request, "_metrics_start", time.perf_counter())

        HTTP_REQUESTS_TOTAL.labels(
            method=request.method, endpoint=endpoint, status=response.status_code
        ).inc()
        HTTP_REQUEST_DURATION_SECONDS.labels(
            method=request.method, endpoint=endpoint
        ).observe(duration)

        return response

    @app.route("/metrics")
    def metrics():
        return generate_latest(), 200, {"Content-Type": CONTENT_TYPE_LATEST}


def record_alerts(alerts: list[dict]) -> None:
    """Incrémente le compteur d'alertes après une exécution du détecteur.

    `alerts` est la liste de dicts renvoyée par DetectionEngine.run()
    (résultat de vars(Alert(...)) pour chaque alerte générée).
    """
    for alert in alerts:
        ALERTS_GENERATED_TOTAL.labels(
            rule_name=alert["rule_name"], severity=alert["severity"]
        ).inc()
