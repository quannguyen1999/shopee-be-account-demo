#Library
FROM openjdk:17-jdk-slim

#Author
MAINTAINER quannguyen1999

#Copy file jar
COPY target/shopee-be-account-demo-0.0.1-SNAPSHOT.jar shopee-be-account-demo-0.0.1-SNAPSHOT.jar

#Excute the application
ENTRYPOINT ["java","-jar","shopee-be-account-demo-0.0.1-SNAPSHOT.jar"]