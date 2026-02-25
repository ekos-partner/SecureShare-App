# Stage 1: Build the frontend
# We use a multi-stage build to keep the final image small.
FROM node:20-slim AS builder
WORKDIR /app

# Install build tools for native modules (better-sqlite3 requires python/make/g++)
# We also run apt-get upgrade to patch OS-level vulnerabilities (e.g., gnutls, zlib)
RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    python3 \
    make \
    g++ \
    && apt-get autoremove -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY package*.json ./
# Install ALL dependencies (including devDependencies) to build the frontend
RUN npm install

COPY . .
# Build the React frontend (Vite) -> outputs to /dist
RUN npm run build

# Stage 2: Production environment
# This is the final image that will run in production.
FROM node:20-slim
WORKDIR /app

# Install runtime dependencies for native modules (better-sqlite3)
# We also run apt-get upgrade to patch OS-level vulnerabilities in the final image
RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    python3 \
    make \
    g++ \
    && apt-get autoremove -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy package files
COPY package*.json ./

# Install dependencies. 
# NOTE: We install devDependencies too because we use 'tsx' to run the server.
# In a strict production setup, you might want to transpile server.ts to JS and use 'node'.
RUN npm install

# Set production environment variable
ENV NODE_ENV=production

# Copy built frontend assets from the builder stage
COPY --from=builder /app/dist ./dist

# Copy backend source files
COPY server.ts .
COPY tsconfig.json .
# We need src/lib because server.ts might import shared types or logic
COPY src/lib ./src/lib
COPY index.html .

# Create a directory for the SQLite database
# We set 777 permissions to avoid permission issues in some container environments (like OpenShift)
RUN mkdir -p /app/data && chmod 777 /app/data
ENV DB_PATH=/app/data/secrets.db

# Expose the port the app runs on
EXPOSE 3000

# Start the server using the npm start script
CMD ["npm", "start"]
