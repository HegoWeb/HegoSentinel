FROM php:8.2-cli-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev \
    libsqlite3-dev \
    curl \
    ca-certificates \
    && docker-php-ext-install pdo pdo_pgsql pdo_sqlite pcntl \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install Node.js 22 for isolated CLI bridge invocation when running local demo scans
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

COPY package.json package-lock.json tsconfig.json ./
COPY types ./types
COPY schemas ./schemas
COPY packages ./packages
COPY integrations ./integrations
COPY examples ./examples
COPY apps/worker ./apps/worker
COPY apps/egress-broker ./apps/egress-broker
COPY apps/api ./apps/api

WORKDIR /workspace/apps/api

EXPOSE 8000

CMD ["php", "-S", "0.0.0.0:8000", "-t", "public", "public/index.php"]

