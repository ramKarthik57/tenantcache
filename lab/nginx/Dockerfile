FROM nginx:1.26.3-alpine
RUN mkdir -p /var/cache/nginx
# Security Notice: This Dockerfile packages an intentionally vulnerable reverse-proxy cache configuration (V1)
# for local benchmarking and vulnerability demonstration. It must only be bound to 127.0.0.1.
COPY lab/nginx/vulnerable/v1_missing_tenant_key.conf /etc/nginx/nginx.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
