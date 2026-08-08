FROM node:26.5.0-alpine3.24@sha256:e88a35be04478413b7c71c455cd9865de9b9360e1f43456be5951032d7ac1a66 AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM node:26.5.0-alpine3.24@sha256:e88a35be04478413b7c71c455cd9865de9b9360e1f43456be5951032d7ac1a66
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev \
    && npm cache clean --force \
    && rm -rf /usr/local/lib/node_modules/npm \
    && rm -f /usr/local/bin/npm /usr/local/bin/npx
COPY --from=build /app/dist ./dist
COPY writer_registry.example.json ./writer_registry.example.json
RUN mkdir -p /app/data /app/bootstrap/public /app/bootstrap/private \
    && chown -R node:node /app/data /app/bootstrap
USER node
CMD ["node", "dist/src/server.js"]
