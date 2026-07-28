# syntax=docker/dockerfile:1

# The client bundle is compiled with the mount point baked in, so BASE_PATH is a
# build argument rather than only a runtime variable. It must match the server's
# BASE_PATH at runtime.
ARG BASE_PATH=""

# --- build ------------------------------------------------------------------
FROM node:20-alpine AS build
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json vite.config.ts ./
COPY client ./client
COPY scripts ./scripts

ARG BASE_PATH
ENV BASE_PATH=${BASE_PATH}
RUN npm run build

# --- runtime ----------------------------------------------------------------
FROM node:20-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production

# Production dependencies only: the build toolchain has no business in the
# image that faces the internet.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY server ./server
COPY --from=build /app/dist ./dist

# Encrypted blobs live here. Mount a volume, or they vanish on redeploy.
ENV DATA_DIR=/data
RUN mkdir -p /data && chown -R node:node /data /app

# Behind Traefik, so X-Forwarded-For is what identifies a client for rate limiting.
ENV TRUST_PROXY=1
ENV PORT=8080
ENV HOST=0.0.0.0

USER node
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8080)+'/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "server/index.js"]
