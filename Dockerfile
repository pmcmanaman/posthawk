# PostHawk - Precision Email Validation Service
# Version: 1.0.0

# Build stage
FROM node:20-alpine as builder

# Frontend build
WORKDIR /app
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ .
RUN npm run build

# Backend build
FROM node:20-alpine

WORKDIR /app
COPY backend/package*.json ./
RUN npm install
COPY backend/ .
COPY --from=builder /app/dist /app/public

EXPOSE 3000
CMD ["npm", "start"]
