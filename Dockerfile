# A5YFAM Agent Games — Proof Gatekeeper (unified endpoint)
# Build context: the agent-games/ directory (this Dockerfile lives at its root).
# The dashboard registers ONE endpoint per agent and sends BOTH tracks'
# tasks to it, so this image also serves Steal the VFY turns: gatekeeper/
# server.js requires ../steal/server.js, which needs circomlibjs.
FROM node:20-slim
WORKDIR /app

# Install production deps only (snarkjs 0.7.6) into gatekeeper/
COPY gatekeeper/package.json gatekeeper/package-lock.json ./gatekeeper/
RUN cd gatekeeper && npm ci --omit=dev

# Steal the VFY deps (snarkjs 0.7.6 + circomlibjs) into steal/
COPY steal/package.json steal/package-lock.json ./steal/
RUN cd steal && npm ci --omit=dev

# Server code + official circuits (paths are relative: server.js reads ../circuits/)
COPY gatekeeper/server.js gatekeeper/keccak.js ./gatekeeper/
COPY steal/server.js steal/keccak.js ./steal/
COPY circuits/ ./circuits/

ENV HOST=0.0.0.0 PORT=8787
EXPOSE 8787
CMD ["node", "gatekeeper/server.js"]
