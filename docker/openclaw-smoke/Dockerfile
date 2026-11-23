# Smoke fixture for the OpenClaw gateway tests. It is not a model for a
# production image: it has no health check, no pinned digest and no hardening
# beyond running as an unprivileged user.
FROM node:24-alpine

WORKDIR /app
COPY server.mjs /app/server.mjs

EXPOSE 8787

# The base image ships an unprivileged `node` user (uid 1000). The server
# listens on 8787, so it needs no privileges.
USER node

CMD ["node", "/app/server.mjs"]
