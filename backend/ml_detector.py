"""
ml_detector.py — Détection d'anomalies comportementales par apprentissage
automatique, en complément des 5 règles à seuils fixes de detector.py.

Approche : un IsolationForest (scikit-learn) apprend un profil "normal" de
comportement par IP source sur la fenêtre analysée (nombre d'événements,
ports distincts ciblés, volume de données, ratio de refus), puis signale les
IP dont le profil s'écarte significativement des autres — utile pour repérer
des comportements inhabituels qui ne correspondent à aucune des 5 signatures
fixes (celles-ci restent nécessaires : un IsolationForest ne "sait" pas ce
qu'est un brute force SSH, il détecte seulement des profils statistiquement
atypiques par rapport au reste du trafic observé).

Limite assumée : un modèle non supervisé entraîné à la volée sur chaque
fenêtre, pas un modèle pré-entraîné et versionné — cohérent avec l'échelle
pédagogique du projet, mais pas la manière dont ça se ferait en production
(entraînement offline périodique, modèle sauvegardé, dérive surveillée).
"""
from datetime import datetime, timedelta

import numpy as np
from sklearn.ensemble import IsolationForest

from database import get_db
from detector import Alert

FEATURES = ["event_count", "distinct_ports", "total_bytes", "deny_ratio"]
MIN_SAMPLES = 5  # trop peu d'IP distinctes -> pas de modèle statistiquement fiable


class MLAnomalyDetector:
    def __init__(self, window_minutes: int = 60, contamination: float = 0.1):
        self.window = window_minutes
        self.since = (datetime.utcnow() - timedelta(minutes=window_minutes)).isoformat()
        self.contamination = contamination

    def _aggregate_by_ip(self) -> list[dict]:
        conn = get_db()
        rows = conn.execute("""
            SELECT
                src_ip,
                COUNT(*) AS event_count,
                COUNT(DISTINCT dst_port) AS distinct_ports,
                COALESCE(SUM(bytes), 0) AS total_bytes,
                SUM(CASE WHEN action = 'DENY' THEN 1 ELSE 0 END)::float / COUNT(*) AS deny_ratio
            FROM logs
            WHERE timestamp >= ?
            GROUP BY src_ip
        """, (self.since,)).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def _detect(self) -> list[Alert]:
        data = self._aggregate_by_ip()
        if len(data) < MIN_SAMPLES:
            return []

        X = np.array([[d[f] or 0 for f in FEATURES] for d in data], dtype=float)
        model = IsolationForest(contamination=self.contamination, random_state=42)
        preds  = model.fit_predict(X)
        scores = model.decision_function(X)

        alerts = []
        for d, pred, score in zip(data, preds, scores):
            if pred != -1:
                continue
            alerts.append(Alert(
                rule_name="Anomalie comportementale (ML)",
                src_ip=d["src_ip"],
                severity="MEDIUM",
                description=(
                    f"Comportement inhabituel détecté par IsolationForest pour {d['src_ip']} "
                    f"sur {self.window} min : {d['event_count']} événements, "
                    f"{d['distinct_ports']} ports distincts, {int(d['total_bytes'])} octets, "
                    f"{d['deny_ratio']:.0%} de refus (score d'anomalie {score:.3f})"
                ),
                timestamp=datetime.utcnow().isoformat(),
                mitre={},
            ))
        return alerts

    def run(self) -> dict:
        """Détecte et persiste les anomalies. Retourne un résumé, même forme
        que DetectionEngine.run() pour rester cohérent côté API/frontend."""
        alerts = self._detect()

        if alerts:
            conn = get_db()
            for a in alerts:
                conn.execute("""
                    INSERT INTO alerts (timestamp, rule_name, src_ip, severity, description, resolved)
                    VALUES (?, ?, ?, ?, ?, 0)
                """, (a.timestamp, a.rule_name, a.src_ip, a.severity, a.description))
            conn.commit()
            conn.close()

        return {
            "alerts_generated": len(alerts),
            "alerts": [vars(a) for a in alerts],
        }
