FROM nginx:1.25-alpine
RUN mkdir -p /var/cache/nginx
COPY lab/nginx/vulnerable/v1_missing_tenant_key.conf /etc/nginx/nginx.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
