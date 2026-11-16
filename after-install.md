# Installation complete

If you accepted dependency preparation and enabled the plugin, open a terminal and run:

```sh
hermes warden setup
```

For a named profile, use the same profile you installed into:

```sh
hermes -p YOUR_PROFILE warden setup
```

Hermes manages the Python environment, including the setup interface. Do not create or activate a separate virtual environment. The bare `warden`/legacy `custodian` shell commands are only guaranteed for a standalone Python package installation; marketplace users should use `hermes warden`.

Setup asks for discovery consent, watched folders and a dashboard login. Installation and setup do not start monitoring or install a service. After saving scope, run `hermes warden scan`, `hermes warden status`, or `hermes warden dashboard` explicitly. Use the same `-p` selector for a named profile.

If you declined dependencies or left the plugin disabled, run `hermes plugins enable hermes-custodian` (with the same profile selector) and accept dependency preparation first. Non-interactive installs can explicitly consent with `hermes plugins install hermes-custodian --yes-deps --enable`; the setup wizard still needs an interactive terminal.

Advanced deployment limit: Hermes currently suppresses plugin CLI commands when `plugins.isolation` is `host`. The command above requires normal local `in_process` plugin loading. Do not disable an existing isolation policy as a workaround; see the standalone instructions in the README for that deployment.
