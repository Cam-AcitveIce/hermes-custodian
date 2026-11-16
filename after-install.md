# Next step: Warden setup

After dependency preparation and enablement, Hermes reports `Terminal command ready: warden`. Then run:

```sh
warden setup
```

No manual pip command, venv creation, activation or `hermes` prefix is required. The launcher uses the Hermes profile you installed into.

After approving and saving scope:

```sh
warden scan
warden status
warden findings
warden dashboard
```

Setup does not start a monitor or install a background service. Discovery, monitoring scope, monitor startup and service persistence remain explicit choices.

If the plugin was left disabled, enable it through `hermes plugins enable hermes-custodian` (using the same `-p PROFILE` selector for a named profile) and accept dependency preparation. Do not overwrite another program's `warden` command if the installer reports a collision.

This branch requires Hermes installer support for `shell_commands`. If no `Terminal command ready` message appears, do not assume the bare command exists: check the README's release status. The public 0.1.0 catalog pin does not include this integration yet.
