# Construction du dashboard puis service par nginx, en deux étapes.
#
# Objectif : `docker compose up -d` suffit à déployer la console, sans exiger
# Node.js sur le serveur ni de `npm run build` lancé à la main — étape
# facilement oubliée, qui laisse alors les analystes sur une version périmée du
# dashboard sans aucun message d'erreur.

FROM node:22-alpine AS build

WORKDIR /app

# Les dépendances sont copiées seules d'abord : la couche est réutilisée tant
# que package.json ne change pas.
COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build


FROM nginx:alpine

COPY --from=build /app/dist /usr/share/nginx/html

# La configuration nginx reste montée depuis deploy/nginx.conf par
# docker-compose : ajuster le proxy ou un en-tête ne doit pas imposer de
# reconstruire l'image.

EXPOSE 80
