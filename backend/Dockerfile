# Build context is the repository root (so the sample datasets can be bundled).
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /src
COPY backend/pom.xml .
RUN mvn -q -B dependency:go-offline
COPY backend/src ./src
RUN mvn -q -B -DskipTests package

FROM eclipse-temurin:21-jre
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 threatlens
COPY --from=build /src/target/threatlens-backend-*.jar app.jar
# Bundled samples; loaded on first boot only when SEED_DIR=/app/seed is set (hosted deployments).
COPY data/sample /app/seed
USER threatlens
EXPOSE 8080
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75", "-jar", "/app/app.jar"]
