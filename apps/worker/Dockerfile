# syntax=docker/dockerfile:1.7

ARG BUN_VERSION=1.1.20

FROM oven/bun:${BUN_VERSION}-slim AS deps
WORKDIR /workspace

COPY package.json bun.lock tsconfig.json ./
COPY apps/api/package.json apps/api/package.json
COPY apps/worker/package.json apps/worker/package.json

RUN bun install --frozen-lockfile --production

FROM oven/bun:${BUN_VERSION}-slim AS verify
WORKDIR /workspace

COPY package.json bun.lock tsconfig.json ./
COPY apps/api/package.json apps/api/package.json
COPY apps/worker/package.json apps/worker/package.json

RUN bun install --frozen-lockfile

COPY apps/worker apps/worker

RUN bun run worker:typecheck

FROM oven/bun:${BUN_VERSION}-slim AS runtime
WORKDIR /app

ENV NODE_ENV=production
ENV METRICS_PORT=9464

RUN adduser --system --uid 1001 bunuser
USER bunuser

COPY --from=deps /workspace/node_modules /app/node_modules
COPY --from=deps /workspace/package.json /app/package.json
COPY --from=deps /workspace/tsconfig.json /app/tsconfig.json
COPY apps/worker /app/apps/worker

EXPOSE 9464

ENTRYPOINT ["bun", "apps/worker/src/index.ts"]
