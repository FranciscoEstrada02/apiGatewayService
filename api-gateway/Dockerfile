# Usa una imagen base de Java para la fase de construcción
FROM maven:3.9.4-eclipse-temurin-21 AS builder

# Establece el directorio de trabajo dentro del contenedor
WORKDIR /app

# Copia los archivos del proyecto (incluyendo pom.xml y src/)
COPY . .

# Ejecuta el empaquetado del proyecto con Maven
RUN mvn clean package -DskipTests

# Usa una imagen base de Java para la ejecución
FROM openjdk:21-jdk-slim

# Establece el directorio de trabajo para la ejecución
WORKDIR /app

# Copia el JAR generado desde la fase de construcción
COPY --from=builder /app/target/*.jar app.jar

# Expón el puerto en el que la aplicación escucha
EXPOSE 8083

# Configura el comando para ejecutar la aplicación
ENTRYPOINT ["java", "-jar", "app.jar"]