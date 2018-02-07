# grafana-proxy

This is a CloudFoundry app that is designed to wrap an existing `bosh-prometheus` Grafana instance that is receiving CloudFoundry firehost exporter and other CF metrics.

This stands up a server that integrates with your CloudFoundry UAA, and will serve paths such as:

`https://grafana.system.example.com/space/<space uuid>/dashboard/file/cf_apps_system.json`

It will ensure that:

1. The user is logged in, by doing OAuth with UAA.
2. That the user show is logged, is a `SpaceDeveloper` for the given space ID.
3. That the only dashboards shown are those hard-coded in the app, and that only metrics associated with applications in that space are displayed.

It is the responsibility of the caller to find a nice way to display a link to this, such as from an existing console.

To deploy, you will want to create a user provided service containing a UAA client, as well as login credentials for your Grafana. See the `main()` method for the values that you'll need.
