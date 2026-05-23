# forger-connect-ml

Microservicio OAuth bridge entre los plugins Forger MercadoLibre y la
API de ML. Stateless, deployable en cualquier proveedor que soporte Node.js.

## Qué hace

- Recibe el flow OAuth del plugin cliente.
- Intercambia credenciales con la API de ML.
- Devuelve tokens firmados al cliente para que guarde la cuenta conectada
  en su DB local.

Código propietario. Sin docs públicas de deployment ni integración.
