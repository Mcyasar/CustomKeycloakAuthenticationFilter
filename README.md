# CustomKeycloakAuthenticationFilter
Java Spring Boot Multiple Authentication Filter By Overriding KeycloakAuthenticationProcessingFilter

In http request header if there is a LoginType:oidc value, the JWTFilter will use Keycloak filter configurations, otherwise the default database loadUser mechanism will 
be used.

If there are two types of login in the client-side, one for default database login mechanism and the other is Keycloak mechanism, by this configurations two login methods
are supported, not only Keycloak mechanism. In the internet, the Keycloak mechanism expamples will support only Keycloak security configuration. Conditional mechanism may
be implemented, yet, the conditional mechanism also will support only one type of authentication filter mechansim by using application properties.
