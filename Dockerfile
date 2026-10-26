# Stage 1: Build the Spring Boot application
FROM maven:3.9-eclipse-temurin-21 AS build

WORKDIR /app

# Copy pom.xml first to take advantage of Docker layer caching
COPY pom.xml .
RUN mvn dependency:go-offline -B || true

# Copy the source code and build the JAR
COPY src ./src
RUN mvn -B -DskipTests clean package \
    && JAR="$(find target -maxdepth 1 -type f -name '*.jar' ! -name '*.original' | head -n 1)" \
    && test -n "$JAR" \
    && cp "$JAR" /app/app.jar

# Stage 2: Runtime image with Eclipse Temurin Java 21 JRE
FROM eclipse-temurin:21-jre

WORKDIR /app

COPY --from=build /app/app.jar /app/app.jar

EXPOSE 8081

# Render supplies the PORT environment variable dynamically (e.g. 10000); 8081 is fallback.
# -XX:MaxRAMPercentage=75.0 prevents JVM OOM errors within container memory limits.
ENTRYPOINT ["sh", "-c", "exec java -XX:MaxRAMPercentage=75.0 -Dserver.port=${PORT:-8081} -jar /app/app.jar"]
