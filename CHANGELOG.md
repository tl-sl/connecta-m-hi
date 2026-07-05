# Changelog

## 1.9.1

- **Zigbee2MQTT `client_id`**: the z2m config written on Apply now sets a unique
  `client_id` (`z2m_<mac>`, path `mqtt.client_id`) via the SMHUB settings API. Without it,
  two SMHUBs bridged to the same HA instance share z2m's default client id and the broker
  kicks them off in a duplicate-client-id disconnect loop (`base_topic` separates topics but
  not the connection). Cleared again on Remove. Requires `zigbee2mqtt ≥ 2.12.1` (the release
  that added the `client_id` schema field).

## 1.9.0

Config-system rework to align with the SMHUB packaging conventions (ahead of hosting on
`pkg.smlight.tech`). The package now integrates through the SMHUB's schema-driven config
system instead of hand-editing files the OS owns.

- **schema.json** moved to `control/` and reformatted to the canonical `system` block
  (`iframe_port`/`service` with types). The SMHUB backend now derives the app registration,
  sidebar entry and stunnel HTTPS port from it.
- **postinst** greatly simplified: no longer writes to the SMHUB backend DB, the opkg lists,
  or stunnel config — it only enables/starts the service (plus cleanup of pre-schema cruft).
- **Zigbee2MQTT** config is now written through the SMHUB packages settings API
  (`POST /api/v1/smhub/packages/zigbee2mqtt/settings`), so it persists in the SMHUB config
  store and is no longer clobbered when the z2m settings page is opened. `configuration.yaml`
  is no longer edited directly.
- **Self-healing boot reconcile removed** — no longer needed now that config lives in the
  SMHUB config store.
- **postrm** added: on uninstall (only), removes the mosquitto bridge config so mosquitto
  returns to local-only mode.
