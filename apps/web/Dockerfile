FROM node:22.14.0-bookworm-slim

WORKDIR /workspace

COPY package.json ./
COPY apps/web ./apps/web
COPY packages ./packages

ENV NODE_ENV=production
ENV PORT=3000
ENV NEXT_PUBLIC_API_URL=http://api:8000

EXPOSE 3000

USER 65532:65532

CMD ["node", "--experimental-strip-types", "apps/web/src/server.ts", "--serve"]

