FROM node:20-slim

RUN apt-get update && apt-get install -y --no-install-recommends openssl ca-certificates && rm -rf /var/lib/apt/lists/*

# ZIA SSL inspection re-signs every TLS connection it inspects, and the build has no Zscaler CA of
# its own - so corepack and pnpm below would fail with UNABLE_TO_GET_ISSUER_CERT_LOCALLY. This is a
# public CA certificate with no private key. NODE_EXTRA_CA_CERTS appends to Node's bundled roots
# rather than replacing them, so public CAs keep working.
COPY zscaler-root-ca.crt /usr/local/share/ca-certificates/zscaler-root-ca.crt
RUN update-ca-certificates
ENV NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/zscaler-root-ca.crt

ENV PNPM_HOME=/pnpm
ENV PATH=$PNPM_HOME:$PATH
RUN corepack enable && corepack prepare pnpm@9 --activate

WORKDIR /app
COPY . .

RUN pnpm install --frozen-lockfile
RUN pnpm build

EXPOSE 3000 5001

CMD ["sh", "-c", "pnpm --filter todo0 exec prisma migrate deploy && pnpm run start:all"]
