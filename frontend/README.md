# Mini-SIEM — Frontend

Dashboard Angular du projet [Mini-SIEM](../README.md) : visualisation en temps
réel des logs réseau, des statistiques, des graphiques et des alertes de
détection générées par le backend Flask.

Voir le [README principal du repo](../README.md) pour le contexte global du
projet, l'architecture complète, le mapping MITRE ATT&CK et les instructions
de lancement via Docker Compose (recommandé).

## Stack technique

- Angular 21 (composants standalone, sans NgModules)
- Chart.js pour les graphiques (répartition des sévérités, top IPs, timeline)
- RxJS / HttpClient pour la communication avec l'API backend

## Lancement en développement

```bash
npm install
ng serve
```

Application disponible sur `http://localhost:4200/`. Par défaut, l'API backend
est attendue sur `http://localhost:5000/api` (voir
`src/environments/environment.ts`).

## Build de production

```bash
ng build
```

Les artefacts sont générés dans `dist/`. Le build de production utilise
`src/environments/environment.prod.ts` (voir `fileReplacements` dans
`angular.json`).

## Tests

```bash
ng test
```

Tests unitaires Jasmine/Karma, notamment sur `LogService` et
`AlertsComponent`.
