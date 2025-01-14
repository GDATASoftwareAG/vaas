You need to set a .env file with the following variables:

```
VAAS_URL=https://gateway.staging.vaas.gdatasecurity.de
TOKEN_URL=https://account-staging.gdata.de/realms/vaas-staging/protocol/openid-connect/token
CLIENT_ID=YOUR_CLIENT_ID
CLIENT_SECRET=YOUR_CLIENT_SECRET
VAAS_USER_NAME=YOUR_USER_NAME
VAAS_PASSWORD=YOUR_PASSWORD
VAAS_CLIENT_ID=vaas-customer
```

## How to run the project

You should use the published Maven package.
If you want to run the examples locally you need to publish a local Maven package with the given gradle task:

```gradle
tasks.register('publishToLocalMaven') {
    group = 'publishing'
    description = 'Publish the library to the local Maven repository (~/.m2/repository).'

    dependsOn 'publishMavenJavaPublicationToMavenLocal'
}
```

You can find the task in the projects root located in `java/build.gradle`.