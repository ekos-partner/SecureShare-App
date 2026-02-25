# Stage 1: Build the frontend and prepare dependencies
FROM node:20-slim AS builder
WORKDIR /app

# Install build tools for native modules (better-sqlite3)
RUN apt-get update && apt-get install -y \
    python3 \
    make \
    g++ \
    && rm -rf /var/lib/apt/lists/*

COPY package*.json ./
# Install ALL dependencies (including devDependencies)
RUN npm install

COPY . .
# Build the React frontend
RUN npm run build

# Stage 2: Production environment
FROM node:20-slim
WORKDIR /app

# Set production environment variables
ENV NODE_ENV=production
ENV DB_PATH=/app/data/secrets.db

# Create data directory and set ownership to 'node' user
RUN mkdir -p /app/data && chown -R node:node /app/data

# Copy built assets and dependencies from builder
# We use --chown to ensure the 'node' user can read/execute these files
COPY --from=builder --chown=node:node /app/dist ./dist
COPY --from=builder --chown=node:node /app/node_modules ./node_modules
COPY --from=builder --chown=node:node /app/package*.json ./
COPY --from=builder --chown=node:node /app/server.ts /app/tsconfig.json /app/index.html ./
COPY --from=builder --chown=node:node /app/src/lib ./src/lib

# Switch to non-root user for security
USER node

# Healthcheck to ensure the API is responding
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD node -e "require('http').get('http://localhost:3000/api/health', (r) => process.exit(r.statusCode === 200 ? 0 : 1))"

# Expose the application port
EXPOSE 3000

# Start the server
CMD ["npm", "start"]
