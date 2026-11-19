FROM node:22.14.0-bookworm-slim

WORKDIR /workspace

COPY package.json tsconfig.json ./
COPY types ./types
COPY packages ./packages
COPY apps/web/package.json apps/web/package-lock.json apps/web/tsconfig.json apps/web/next.config.ts apps/web/components.json ./apps/web/
COPY apps/web/src ./apps/web/src

WORKDIR /workspace/apps/web
RUN npm ci --no-audit --no-fund && npm run build && chown -R 65532:65532 /workspace/apps/web

ENV NODE_ENV=production
ENV PORT=3000
ENV HOST=0.0.0.0
ENV HEGOSENTINEL_API_UPSTREAM_URL=http://api:8000

EXPOSE 3000
USER 65532:65532

CMD ["npm", "run", "start"]
