// Environnement de développement (ng serve)
// Note sécurité : la clé API est embarquée dans le bundle JS et donc visible
// de tout utilisateur du navigateur (devtools). C'est acceptable ici car le
// projet est pédagogique et sans authentification utilisateur réelle ; ne pas
// reproduire ce pattern pour protéger de vraies données sensibles.
// Doit correspondre à API_KEY côté backend (voir backend/.env.example).
export const environment = {
  production: false,
  apiUrl: 'http://localhost:5000/api',
  apiKey: 'change-me',
};
