# Shoppe-be-account-demo

# Run docker
# Step 0 run file jar
mvn install -DskipTests -Dmaven.test.skip=true

# Step 0 install postgres first 
docker run --name postgres -p 5431:5432 POSTGRES_PASSWORD=postgres -d postgres

# Step 1 build
docker build . -t quannguyen1999/shopee-be-account-demo
# or
mvn spring-boot:build-image (reject - buildpack to slow - #TODO had bug)
# or
mvn compile jib:dockerBuild (use this - google job fastest - #TODO had bug)

# Step 2 run 
docker run -d -p 8070:8070 quannguyen1999/shopee-be-account-demo
# or to get log
docker run --name shopee-be-account-demo -p 8070:8070 quannguyen1999/shopee-be-account-demo

# this project will always redirect login page 
http://localhost:8070