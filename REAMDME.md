# Mini-SIEM — Système de détection d'intrusion réseau

Dashboard de sécurité temps réel développé en Python/Flask + Angular.

## Fonctionnalités
- Ingestion et analyse de logs réseau en temps réel
- Détection d'anomalies : Brute Force SSH, Port Scan, Exfiltration de données
- Score de risque dynamique (0-100)
- Dashboard interactif avec graphiques Chart.js
- Filtres avancés, recherche full-text, export CSV
- Conteneurisation complète avec Docker

## Stack technique
- **Backend** : Python, Flask, SQLite
- **Frontend** : Angular 21, Chart.js
- **DevOps** : Docker, docker-compose
- **Cybersécurité** : Détection SIEM, règles IDS, scoring de risque

## Lancement rapide
```bash
# Sans Docker
cd backend && python app.py
cd frontend && ng serve

# Avec Docker
docker-compose up --build
```

