# forger-connect-ml

Microservicio OAuth bridge entre los plugins Forger MercadoLibre y la
API de ML. Stateless, deployable en cualquier proveedor que soporte Node.js.

## Qué hace

- Recibe el flow OAuth del plugin cliente.
- Intercambia credenciales con la API de ML.
- Devuelve tokens firmados al cliente para que guarde la cuenta conectada
  en su DB local.

Código propietario. Sin docs públicas de deployment ni integración.

## Órdenes: ritmos y barrido (v2.11.0)

Todas son opcionales; sin configurar nada, valen los valores por defecto.

| Variable | Por defecto | Qué hace |
|---|---|---|
| `WFML_ORDER_INTERVAL` | `20000` (ms; mínimo 15000) | Cada cuánto el loop de órdenes baja de ML las que entraron por aviso. Antes, 60000. |
| `WFML_ORDER_SWEEP_ENABLED` | prendido | `0` apaga el barrido periódico de órdenes. |
| `WFML_ORDER_SWEEP_INTERVAL` | `300000` (ms; mínimo 15000) | Cada cuánto se barre cada cuenta: `/orders/search` por fecha de última actualización y se encola lo que el aviso no trajo. |
| `WFML_ORDER_SWEEP_OVERLAP_MIN` | `10` | Minutos de solapamiento con la pasada anterior. |
| `WFML_ORDER_SWEEP_GRACE_SEC` | `120` | Segundos que se espera el aviso de una orden recién actualizada antes de barrerla. |
| `WFML_ORDER_SWEEP_MAX_HOURS` | `72` | Tope hacia atrás: la primera vez, o después de una caída más larga, se barren sólo estas horas (nunca antes del alta de la cuenta en el conector). |
| `WFML_ORDER_SWEEP_WINDOW_MIN` | `360` | Tamaño de cada ventana de una recuperación larga; el cursor avanza ventana por ventana. |
| `WFML_ORDER_SWEEP_PAUSE_MS` | `250` | Pausa entre páginas de ML. Un 429 corta la pasada de esa cuenta y la saltea con espera creciente (tope 30 min). |

Lo que trajo cada pasada queda en la tabla `order_sweeps` (`db/013`) y en el registro
(`[sweep] cuenta …: se encolaron N que el aviso no había traído`); las filas de
`order_events` que encoló el barrido llevan `source = 'sweep'`. `GET /v1/orders/status`
le da al sistema el estado de la cola y del barrido de cada cuenta (punto de salud y avisos).
