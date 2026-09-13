FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist/frontend/browser /usr/share/nginx/html
COPY nginx.conf.template /etc/nginx/templates/default.conf.template
ENV BACKEND_HOST=backend:5000
# Active le script d'entrée officiel qui exporte NGINX_LOCAL_RESOLVERS (lu
# depuis /etc/resolv.conf) pour un "resolver" dynamique dans le template.
ENV NGINX_ENTRYPOINT_LOCAL_RESOLVERS=1
EXPOSE 80