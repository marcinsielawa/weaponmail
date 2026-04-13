# --- STAGE 1: Build Angular Frontend ---
FROM node:22-alpine AS frontend-build
WORKDIR /app/frontend

# Copy package files and install dependencies
COPY frontend/package*.json ./
RUN npm install

# Copy source and build (output usually goes to /app/frontend/dist/frontend/browser)
COPY frontend/ ./
RUN npm run build

# --- STAGE 2: Build Spring Boot Backend ---
FROM maven:3-eclipse-temurin-25-alpine AS backend-build
WORKDIR /app/backend

# Copy the pom.xml and download dependencies (for caching)
COPY backend/pom.xml ./
RUN mvn dependency:go-offline -B

# Copy the backend source
COPY backend/src ./src

# Copy the built Angular files from Stage 1 into Spring Boot's static resources
# Note: Check your 'dist' folder structure. Angular 17+ usually uses 'dist/<project-name>/browser'
COPY --from=frontend-build /app/frontend/dist/frontend/browser ./src/main/resources/static/

# Build the jar
RUN mvn package -DskipTests

# --- STAGE 3: Final Runtime ---
FROM eclipse-temurin:25-jre-alpine
WORKDIR /app

# Create a non-root user for security
RUN addgroup -S weaponmail && adduser -S weaponmail -G weaponmail
USER weaponmail

# Copy the jar from the build stage
COPY --from=backend-build /app/backend/target/*.jar app.jar

EXPOSE 8080

# standard Spring Boot env vars can be overridden in docker-compose
ENTRYPOINT ["java", "-jar", "app.jar"]
