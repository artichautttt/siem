// Environnement de développement (ng serve). L'authentification se fait
// désormais par login JWT (voir services/auth.service.ts) — plus de clé API
// embarquée dans le bundle.
export const environment = {
  production: false,
  apiUrl: 'http://localhost:5000/api',
};
