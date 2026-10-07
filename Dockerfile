FROM node:20-alpine
WORKDIR /app
COPY package.json ./
COPY server.js ./
COPY index.html ./
COPY style.css ./
COPY app.js ./
RUN mkdir -p data
EXPOSE 10000
CMD ["npm","start"]