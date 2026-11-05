FROM composer:2.8 AS composer_bin
FROM php:8.2-cli-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev \
    libsqlite3-dev \
    unzip \
    git \
    curl \
    ca-certificates \
    && docker-php-ext-install pdo pdo_pgsql pgsql pdo_sqlite pcntl \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY --from=composer_bin /usr/bin/composer /usr/bin/composer

# Install Node.js 22 for isolated CLI bridge invocation when running offline fixture evaluations
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

COPY package.json package-lock.json tsconfig.json ./
COPY types ./types
COPY schemas ./schemas
COPY packages ./packages
COPY integrations ./integrations
COPY scripts ./scripts
COPY examples ./examples
COPY apps/worker ./apps/worker
COPY apps/egress-broker ./apps/egress-broker
COPY apps/api ./apps/api

WORKDIR /workspace/apps/api
RUN composer install --no-dev --no-interaction --optimize-autoloader --no-scripts \
    && mkdir -p storage/logs bootstrap/cache database \
    && chown -R 65532:65532 /workspace/apps/api/storage /workspace/apps/api/bootstrap/cache /workspace/apps/api/database

USER 65532:65532
EXPOSE 8000

CMD ["php", "artisan", "serve", "--host=0.0.0.0", "--port=8000"]
