FROM maven:3.9.11-eclipse-temurin-24-alpine AS build
WORKDIR /app
COPY ./src ./src
COPY ./pom.xml ./pom.xml
RUN mvn clean package -DskipTests

FROM openjdk:24-jdk
WORKDIR /app
COPY --from=build /app/target/*.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]