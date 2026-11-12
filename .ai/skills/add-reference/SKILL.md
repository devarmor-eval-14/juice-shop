# AI Assistant Security Rules – Test

## Scope

Apply these rules to shopper traffic crossing the public network ↔ application cluster boundary, Payment service charge handling and logs, and Cart service gRPC access within the cluster. Review frontend and ingress configuration, Payment service logging, Cart service authorization, and cluster network policy whenever changes touch those flows.

## System & Security Context

- Shopper requests may carry session identifiers or checkout details. The catalog assumes a reachable port-80 deployment and a cart cookie without the `Secure` attribute; deployment exposure must be verified in the relevant configuration.
- Payment service receives charge requests containing card numbers and CVVs. Its full-request logging in `src/paymentservice/server.js` is an assumption to verify; `src/paymentservice/charge.js` is described as logging only the last four digits.
- The described internal services use insecure gRPC and have no specified internal authentication. `helm-chart/values.yaml` defaults `networkPolicies.create` to false. Cart-service abuse requires a foothold in an application-cluster workload.

## Global Security Principles

- Protect sensitive values before they cross a trust boundary; a redirect cannot undo an HTTP disclosure.
- Keep session identifiers and checkout details off plaintext shopper requests.
- Log only explicitly selected, non-sensitive diagnostics, including on validation and error paths.
- Treat network reachability and possession of a cart identifier as insufficient authority.
- Restrict internal connections to workloads with an approved need, then authenticate and authorize each caller and operation.
- Check security behavior through observable requests, responses, and emitted logs, including failure cases.

## Control: Encrypted transport for shopper sessions (`encrypted-storefront-transport`)

- **Priority:** Highest
- **Status:** Suggested — intended guidance pending adoption; address first because session and checkout data can cross the public boundary.
- **Related threat:** Shopper cart impersonation through a session cookie exposed over the default HTTP endpoint (`http-session-cookie-replay`, Spoofing). **Trust boundary:** Public network ↔ Application cluster.
- **When this rule applies:** Storefront frontend and public ingress changes affecting shopper sessions, cart cookies, or checkout requests.
- **Required behaviour:**
  - Serve requests carrying session identifiers or checkout details only over HTTPS. Reject or prevent plaintext submission before those values are transmitted.
  - Configure public exposure and cookies so session identifiers are never sent over HTTP; set the session cookie `Secure` attribute where the cookie is issued.
  - Do not count an HTTP-to-HTTPS redirect as protection when the initial HTTP request already carries sensitive values.
  - Verify actual ingress and port-80 behavior in `README.md`, `kubernetes-manifests/`, and `.github/release-cluster/`; the proposed frontend check is a review starting point, not a required location.
- **Tests to consider:**
  - An HTTP request containing a session identifier is rejected before the application accepts it; no sensitive value is transmitted in a redirect flow.
  - An HTTP checkout request containing checkout details is not accepted or processed.
  - An HTTPS shopper request succeeds and its session cookie has the `Secure` attribute.
  - The deployed public endpoint and port-80 behavior match the intended HTTPS enforcement.

## Control: Card-data exclusion from application logs (`payment-log-data-minimization`)

- **Priority:** Highest
- **Status:** Suggested — intended guidance pending adoption; address first because emitted logs can disclose card data to log readers.
- **Related threat:** Card-data exposure to log readers because the payment service records complete charge requests (`payment-card-details-in-logs`, Information Disclosure).
- **When this rule applies:** Payment service charge handling and every log path that can observe a charge request, especially `src/paymentservice/server.js` and `src/paymentservice/charge.js`.
- **Required behaviour:**
  - Never emit a full card number or CVV in application logs, including validation and error paths.
  - Log only a fixed set of non-sensitive charge diagnostics; do not log complete charge request objects.
  - Inspect the assumed full-request logging in `src/paymentservice/server.js` and remove it if present. Do not rely on later log deletion to protect card data.
- **Tests to consider:**
  - A successful charge emits no full card number or CVV.
  - An invalid charge request emits no full card number or CVV.
  - A charge error emits no full card number or CVV, even when request details are included in an error object.
  - Emitted diagnostics contain only the intended non-sensitive fields.

## Control: Authorized callers only for cart operations (`authorized-callers-only-for-cart-operations`)

- **Priority:** High
- **Status:** Suggested — intended guidance pending adoption.
- **Related threat:** Unauthorized cart access from a compromised workload through unauthenticated internal gRPC (`cluster-foothold-cart-service-impersonation`, Elevation of Privilege).
- **When this rule applies:** Cart service gRPC handlers and client connections, plus cluster network policies governing access to the cart endpoint.
- **Required behaviour:**
  - Enable narrowly scoped network policies that allow connections to the cart endpoint only from workloads with an approved cart-operation need.
  - Authenticate workload identity on the gRPC channel and authorize each requested cart operation for that identity.
  - Reject callers that lack permission for the operation even if they can reach Cart service and provide a valid session identifier.
  - Do not treat cluster location, an unexposed service address, or a caller-supplied cart identifier as proof of authority.
- **Tests to consider:**
  - An approved workload can connect and perform its authorized cart operations.
  - An unapproved workload cannot connect under the deployed network policy.
  - A reachable caller without authenticated workload identity is rejected.
  - An authenticated caller denied a specific operation is rejected even with a valid session identifier.