FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
# Exécution sans privilèges (Trivy DS-0002) : UID numérique pour que
# runAsNonRoot soit vérifiable côté Kubernetes.
RUN useradd --system --uid 10001 --no-create-home app
USER 10001
EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:5000/api/health || exit 1
CMD ["gunicorn", "-w", "4", "--preload", "-b", "0.0.0.0:5000", "app:app"]