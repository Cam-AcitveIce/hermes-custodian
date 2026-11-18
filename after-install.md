# Next step: set up Warden

```sh
hermes warden setup
```

Setup asks which Hermes profiles and folders Warden may watch. Nothing is monitored until you approve it, and setup doesn't install or start anything in the background.

Then:

```sh
hermes warden scan        # first scan
hermes warden findings    # what needs attention
hermes warden dashboard   # local web dashboard
```

For a named profile, add `-p <profile>` after `hermes`. Your agent can also use the `warden_status`, `warden_findings`, `warden_changes` and `warden_scan` tools.

If the plugin was left disabled, run `hermes plugins enable hermes-custodian` and accept the dependency prompt.
