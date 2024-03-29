# poc-middleware

Proof Of Concept of a webservice enabled middleware, using OpenAPI 3.1 and OAuth 2.

Intended to be used with the [poc-backend](https://github.com/kb-dk/poc-backend) project.


Developed and maintained by the Royal Danish Library.

## Requirements

* Maven 3                                  
* Java 11

## Setup

* Ensure a poc-backend is running where it can be reached by the local machine
* Install a Tomcat 9+
* Adjust and add the configurations, as described in [DEVELOPER.md](DEVELOPER.md)
* Add the WAR file generated by `mvn package`.


## Build & run

Build with
``` 
mvn package
```

Test the webservice with
```
mvn jetty:run
```

The Swagger UI is available at <http://localhost:9061/poc-middleware/api/>. 

## OAuth2 and OpenAPI

As a general rule, access to services is controlled by [OAuth2](https://oauth.net/2/).
This project has build-in support for the setup used at the Royal Danish Library, which should conform to the
overall standard.

## OAuth2

Base OAuth2 setup is done in the projects [configuration files](conf/poc-middleware-behaviour.yaml). The sample
config is annotated with comments describing the parameters, but it boils down to defining which OAUth2 server to
use and which realms to accept.

For local testing of the endpoints, set `mode: OFFLINE` in the developer config to disable signature checking and
access restriction for the endpoints.

To request an access token manually, call

```
curl -s --location --request POST 'https://<oauthserver>/auth/realms/<realm>/protocol/openid-connect/token'
  --header 'Content-Type: application/x-www-form-urlencoded' 
  -d 'grant_type=password' -d 'client_id=<clientid>' -d 'username=<user>' -d "password=<password>" 
  -d 'client_secret=<clientsecret>'
```

Talk to a developer familiar with OAUth2 about getting the variables for the call:

 * `oauthserver`: (Probably) a Keycloak-server at the Royal Danish Library
 * `realm`: The realm to use. This must match the realm defined for the OpenAPI
 * `clientid`: The ID for the client defined at the oauthserver
 * `user`: The user defined for the client. As a developer, this will probably be one's standard username for the AD  
 * `password`: The password for the user. As a developer, this will probably be one's standard password for the AD  
 * `clientsecret`: Key needed to request a token from the clientid, e.g. `7eec0aeb-1ae8-4074-801b-270ad79fbc48`

**TODO**: Describe how to call an endpoint with curl, providing the access token.


### OpenAPI

The endpoints in the [sample OpenAPI](src/main/openapi/openapi_v1.yaml) has a mix of authorization requirements.  

The general setup of authorization is under `components:securitySchemes` at the bottom.  The "Project specific roles"
should probably be adjusted to the concrete project but normally that would be the only change to that part.

Individual endpoints can be extended with `security` if access should be restricted.
See the [sample OpenAPI](src/main/openapi/openapi_v1.yaml) for examples. The `security` part states which roles are
required to call the methods. Two roles are meta-roles:
 
* `public`: Anyone can call the method, but if the call has an OAuth2 accessToken, the roles specified in the token might give extra privileges (access to more material, extended metadata etc.)
 * `any`: An accessToken is required for the endpoint, but no specific role is needed. It is up to the implementation to . 

The generated API and skeleton implementation will be OAuth2-enabled after this. If access is determined solely on
roles defines in the realm, no further action is required. If the endpoint is marked with `public` or `any`, getting
a list of the roles for the caller is normally needed.

The endpoint `whoami` demonstrates retrieval of roles and other metadata from the OAuth process.
At the core it is simply
```java
    Object roles = JAXRSUtils.getCurrentMessage().get(KBAuthorizationInterceptor.TOKEN_ROLES);
```
where the `roles` Object (if defined) is a `Set<String>`. In order for this to work it must be done in the calling
Thread; if supporting classes needs roles they should be resolved in the endpoint implementation class and explicitly
provided as arguments in the method calls, e.g.
```java
    @Override
    public String readBook(String id){
        Object rolesObj = JAXRSUtils.getCurrentMessage().get(KBAuthorizationInterceptor.TOKEN_ROLES);
        Set<String> roles = rolesObj == null ? Collection.emptySet() : (Set<String>)rolesObj;
        BookHandler.getInstance().retrieveBook(id, roles);
        ...
    }
```

## Other

See the file [DEVELOPER.md](DEVELOPER.md) for developer specific details and how to deploy to tomcat.
