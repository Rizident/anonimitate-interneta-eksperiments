## Summary per variant
| variant | queries | captured | marker visible | observed == model | slope (B/char) | intercept | R^2 |
|---|---|---|---|---|---|---|---|
| dns_udp | 80 | 80 | 80/80 | 80/80 | 1.000 | 18.0 | 1.0000 |
| http_plain | 80 | 80 | 80/80 | 80/80 | 1.000 | 182.0 | 1.0000 |
| doh | 80 | 80 | 0/80 | 80/80 | 1.000 | 199.0 | 1.0000 |
| doh_pad | 80 | 80 | 0/80 | 80/80 | 0.000 | 310.0 | constant |

## TLS metadata visible to the observer (doh, doh_pad)
- SNI values seen in ClientHello: ['doh.resolver.test']
- ClientHello record length: min 1472 B, max 1472 B

## Mean observed size (bytes) by domain-name length
| name length L | dns_udp | http_plain | doh | doh_pad |
|---|---|---|---|---|
| 19 | 37.0 | 201.0 | 218.0 | 310.0 |
| 26 | 44.0 | 208.0 | 225.0 | 310.0 |
| 33 | 51.0 | 215.0 | 232.0 | 310.0 |
| 40 | 58.0 | 222.0 | 239.0 | 310.0 |
| 47 | 65.0 | 229.0 | 246.0 | 310.0 |
| 54 | 72.0 | 236.0 | 253.0 | 310.0 |
| 61 | 79.0 | 243.0 | 260.0 | 310.0 |
| 68 | 86.0 | 250.0 | 267.0 | 310.0 |
