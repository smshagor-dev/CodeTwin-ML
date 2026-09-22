ALTER TABLE source_routes
  ADD COLUMN router_prefix TEXT NOT NULL DEFAULT '';

ALTER TABLE source_route_mounts
  ADD COLUMN prefix_mode TEXT NOT NULL DEFAULT 'prepend'
  CHECK(prefix_mode IN ('prepend','override_router_prefix'));
