#Library
FROM openjdk:17-jdk-slim

#Author
MAINTAINER quannguyen1999

# Install CURL
RUN apt-get update && apt-get install -y curl

#Copy file jar
COPY target/shopee-be-account-demo-latest.jar shopee-be-account-demo-latest.jar

#Excute the application
ENTRYPOINT ["java","-jar","shopee-be-account-demo-latest.jar"]