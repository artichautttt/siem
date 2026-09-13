// Environnement de production (build `ng build`, servi par nginx via Docker).
// Le conteneur nginx du frontend relaie /api vers le backend (voir
// frontend/nginx.conf.template) : une URL relative fonctionne aussi bien
// derrière docker-compose (EC2) que derrière l'Ingress Kubernetes, sans
// dépendre du nom d'hôte/port utilisé pour accéder au frontend.
export const environment = {
  production: true,
  apiUrl: '/api',
  apiKey: 'change-me',
};
