# syntax=docker/dockerfile:1
FROM node:24.21.0-alpine3.24 AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:1.30.5-alpine3.24
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
# Run as the unprivileged nginx user on a high port.
RUN chown -R nginx:nginx /var/cache/nginx /var/run /usr/share/nginx/html \
  && sed -i '/^user /d' /etc/nginx/nginx.conf \
  && sed -i 's#pid .*#pid /tmp/nginx.pid;#' /etc/nginx/nginx.conf
USER nginx
EXPOSE 8080
