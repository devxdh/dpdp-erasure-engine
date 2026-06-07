# syntax=docker/dockerfile:1.7

ARG BUN_VERSION=1.3.12

FROM oven/bun:${BUN_VERSION}-slim AS deps
WORKDIR /workspace

COPY . .
RUN bun install --frozen-lockfile --production

FROM oven/bun:${BUN_VERSION}-slim AS verify
WORKDIR /workspace

COPY . .
RUN bun install --frozen-lockfile

RUN bun run worker:typecheck

FROM oven/bun:${BUN_VERSION}-slim AS runtime
WORKDIR /app

ENV NODE_ENV=production
ENV METRICS_PORT=9464

COPY --from=deps /workspace/node_modules /app/node_modules
COPY --from=deps /workspace/package.json /app/package.json
COPY --from=deps /workspace/tsconfig.json /app/tsconfig.json
COPY apps/worker /app/apps/worker

EXPOSE 9464

WORKDIR /app/apps/worker
ENTRYPOINT ["bun", "src/index.ts"]