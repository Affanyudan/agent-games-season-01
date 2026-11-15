# A5YFAM Agent Games — Proof Gatekeeper
# Build context: the agent-games/ directory (this Dockerfile lives at its root).
FROM node:20-slim
WORKDIR /app

# Install production deps only (snarkjs 0.7.6) into gatekeeper/
COPY gatekeeper/package.json gatekeeper/package-lock.json ./gatekeeper/
RUN cd gatekeeper && npm ci --omit=dev

# Server code + official circuits (paths are relative: server.js reads ../circuits/)
COPY gatekeeper/server.js gatekeeper/keccak.js ./gatekeeper/
COPY circuits/ ./circuits/

ENV HOST=0.0.0.0 PORT=8787
EXPOSE 8787
CMD ["node", "gatekeeper/server.js"]
