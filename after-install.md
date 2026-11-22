# Next step: set up Warden

```sh
hermes warden setup
```

Setup asks which Hermes profiles and folders Warden may watch. Nothing is monitored until you approve it, and setup doesn't install or start anything in the background.

Then:

```sh
hermes warden scan        # run an antivirus & security threat scan
hermes warden findings    # see detected threats & evidence
hermes warden apps        # list installed plugins, MCP servers & OS apps
hermes warden dashboard   # local authenticated web console
```

Permission-bit checks on auth/`.env` files are off by default (toggleable in the dashboard under **Coverage & Scope**). Sensitive credential, memory, and chat-history files are never opened or read.

For a named profile, add `-p <profile>` after `hermes`. Your agent can also use the four read-only tools: `warden_status`, `warden_findings`, `warden_changes` and `warden_scan`.

If the plugin was left disabled, run `hermes plugins enable hermes-custodian` and accept the dependency prompt.
