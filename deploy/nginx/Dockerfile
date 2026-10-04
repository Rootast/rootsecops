FROM nginx:1.27-alpine

RUN apk add --no-cache openssl

COPY default.conf.template /etc/nginx/templates/default.conf.template
COPY 10-generate-self-signed-cert.sh /docker-entrypoint.d/10-generate-self-signed-cert.sh

RUN chmod 0755 /docker-entrypoint.d/10-generate-self-signed-cert.sh
