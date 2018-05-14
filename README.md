# grafana-proxy

This is a CloudFoundry app that is designed to wrap an existing `bosh-prometheus` Grafana instance that is receiving CloudFoundry firehost exporter and other CF metrics.

This stands up a server that integrates with your CloudFoundry UAA, and will serve paths such as:

`https://grafana.system.example.com/space/<space uuid>/dashboard/file/cf_apps_system.json`

It will ensure that:

1. The user is logged in, by doing OAuth with UAA.
2. That the user who is logged in, is a `SpaceDeveloper` for the given space ID.
3. That the only dashboards shown are those hard-coded in the app, and that only metrics associated with applications in that space are displayed.

It is the responsibility of the caller to find a nice way to display a link to this, such as from an existing console.

To deploy, you will want to create a user provided service containing a UAA client, as well as login credentials for your Grafana. See the `main()` method for the values that you'll need.

## Run locally for testing

```bash
export DOMAIN=example.com
export CLIENT_SECRET=xxxxxx
export GRAFANA_PASSWORD=xxxxxx
export CSRF_KEY=$(openssl rand -hex 32)
export COOKIE_AUTH_KEY=$(openssl rand -hex 64)
export COOKIE_ENCRYPTION_KEY=$(openssl rand -hex 32)
export UAA_URL=https://uaa.system.${DOMAIN}
export CF_API_URL=https://api.system.${DOMAIN}
export EXTERNAL_URL=http://localhost:8080
export PORT=8080
export CLIENT_ID=grafana-proxy-client
export GRAFANA_URL=https://grafana.monitoring.${DOMAIN}
export GRAFANA_USERNAME=admin
export INSECURE_COOKIES=true
```
