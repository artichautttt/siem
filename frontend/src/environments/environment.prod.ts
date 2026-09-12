// Environnement de production (build `ng build`, servi par nginx via Docker).
// Note : le conteneur nginx du frontend ne fait actuellement PAS de reverse
// proxy vers le backend (voir frontend/Dockerfile) — le navigateur appelle donc
// directement le backend Flask exposé par docker-compose sur le port 5000 de
// l'hôte. Si un reverse proxy nginx est ajouté plus tard, remplacer cette
// valeur par '/api'.
export const environment = {
  production: true,
  apiUrl: 'http://localhost:5000/api',
  apiKey: 'change-me',
};
