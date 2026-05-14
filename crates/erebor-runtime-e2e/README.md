# erebor-runtime-e2e

End-to-end harnesses for running erebor runtimes against process-local fixtures and, later, real external systems.

The default tests are deterministic and use a mini CDP websocket upstream. Real browser checks are opt-in:

```sh
EREBOR_E2E_CHROME_WS=ws://127.0.0.1:9222/devtools/browser/<id> \
  cargo test -p erebor-runtime-e2e -- --ignored
```

