#User JDK 17
FROM openjdk:17-jdk-slim

#Author Maintain
MAINTAINER quannguycen

#Copy File Jar to Docker
COPY target/shopee-be-account-demo-0.0.1-SNAPSHOT.jar shopee-be-account-demo-0.0.1-SNAPSHOT.jar

#Excute command to run Spring boot
#Cmd Example: java -jar target/shopee-be-account-demo-0.0.1-SNAPSHOT.jar
ENTRYPOINT [ \
    "java", \
    "-jar", \
    "shopee-be-account-demo-0.0.1-SNAPSHOT.jar" \
]

