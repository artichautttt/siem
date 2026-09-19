FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build

# Image nginx officielle "unprivileged" : tourne en non-root (UID 101) et écoute
# sur 8080 au lieu de 80 (un non-root ne peut pas lier un port < 1024).
FROM nginxinc/nginx-unprivileged:alpine
COPY --from=build /app/dist/frontend/browser /usr/share/nginx/html
COPY nginx.conf.template /etc/nginx/templates/default.conf.template
ENV BACKEND_HOST=backend:5000
# Active le script d'entrée officiel qui exporte NGINX_LOCAL_RESOLVERS (lu
# depuis /etc/resolv.conf) pour un "resolver" dynamique dans le template.
ENV NGINX_ENTRYPOINT_LOCAL_RESOLVERS=1
USER 101
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -q --spider http://localhost:8080/ || exit 1