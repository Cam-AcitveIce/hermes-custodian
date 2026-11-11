"""Explicit user entrypoints. Import heavy interfaces only when requested."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import sys


def default_state_dir():
    profile = os.environ.get('HERMES_HOME')
    if profile:
        return Path(profile) / 'plugin-data' / 'hermes-custodian'
    return Path(os.environ.get('XDG_STATE_HOME', Path.home() / '.local/state')) / 'hermes-custodian'


def _is_root_owned_install() -> bool:
    import stat
    for target in (Path(__file__).resolve(), Path(sys.executable).resolve()):
        for current in (target, *target.parents):
            try:
                info = os.lstat(current)
            except OSError:
                return False
            if info.st_uid != 0 or (info.st_mode & 0o022) != 0 or stat.S_ISLNK(info.st_mode):
                return False
    return True


def _set_dashboard_login(state_dir):
    """Masked-prompt login setup. The password is never echoed, logged or accepted as an argument."""
    from getpass import getpass
    from .dashboard_auth import DashboardAuth
    username = input('Dashboard username: ').strip()
    password = getpass('New password/passphrase (minimum 12 characters): ')
    confirmation = getpass('Confirm password: ')
    if password != confirmation:
        raise ValueError('Passwords did not match; nothing changed')
    DashboardAuth(state_dir).configure(username, password)
    print('Dashboard login saved. Password-reset sessions are invalidated on their next request.')


def _offer_dashboard_login(state_dir):
    """After first-run setup, offer the dashboard login once so a new user is never left guessing."""
    from .dashboard_auth import DashboardAuth
    from .engine import Engine
    if not Engine(state_dir).status().get('configured') or DashboardAuth(state_dir).configured():
        return 0
    answer = input('Set a dashboard login now? Used to sign in to `custodian dashboard`. [Y/n] ').strip().lower()
    if answer in ('n', 'no'):
        print('Skipped. Set it any time with: custodian dashboard-credentials')
        return 0
    try:
        _set_dashboard_login(state_dir)
    except (ValueError, OSError) as exc:
        print(f'Custodian: {exc}. Your scope is saved; set the dashboard login with: custodian dashboard-credentials', file=sys.stderr)
        return 1
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog='custodian', description='Local security monitoring. Your scope. Your decisions.')
    parser.add_argument('--state-dir', type=Path, default=default_state_dir())
    subs = parser.add_subparsers(dest='command', required=True)
    subs.add_parser('dashboard-credentials', help='Set or reset local dashboard username/password using masked terminal prompts')
    for name, help_text in [('setup', 'Configure consent and scope in the setup TUI'), ('tui', 'Open the terminal control centre'), ('scan', 'Run a bounded scan of approved paths'), ('status', 'Show monitoring health and coverage'), ('findings', 'Show evidence-backed findings'), ('events', 'Show recent changes'), ('monitor', 'Run the foreground monitoring workload'), ('dashboard', 'Launch an authenticated loopback dashboard'), ('updates', 'Check native OS updates without applying them')]:
        cmd = subs.add_parser(name, help=help_text)
        if name == 'monitor':
            cmd.add_argument('--once', action='store_true', help='Run one monitoring cycle and exit')
        if name == 'dashboard':
            cmd.add_argument('--port', type=int, default=0)
        if name == 'updates':
            upd_subs = cmd.add_subparsers(dest='updates_action', required=False)
            plan_cmd = upd_subs.add_parser('security-plan', help='Preview native security-only unattended-upgrades policy (read-only)')
            plan_group = plan_cmd.add_mutually_exclusive_group(required=True)
            plan_group.add_argument('--enable', dest='security_enabled', action='store_true')
            plan_group.add_argument('--disable', dest='security_enabled', action='store_false')
            apply_cmd = upd_subs.add_parser('security-apply', help='Apply previewed security-only policy as root from a root-owned install')
            apply_cmd.add_argument('--plan-id', required=True)
            apply_group = apply_cmd.add_mutually_exclusive_group(required=False)
            apply_group.add_argument('--enable', dest='security_enabled', action='store_const', const=True, default=None)
            apply_group.add_argument('--disable', dest='security_enabled', action='store_const', const=False, default=None)
    svc = subs.add_parser('service', help='Explicit user-service lifecycle management')
    svc.add_argument('action', choices=['install', 'start', 'status', 'stop', 'uninstall'])
    svc.add_argument('--enable', action='store_true', help='Explicitly enable the installed service at user startup')
    args = parser.parse_args(argv)
    if args.command in ('setup', 'tui', 'dashboard-credentials') and not (sys.stdin.isatty() and sys.stdout.isatty()):
        parser.error('setup/tui/dashboard-credentials requires an interactive terminal; unattended launches never open a wizard')
    try:
        if args.command == 'dashboard-credentials':
            _set_dashboard_login(args.state_dir)
            return 0
        if args.command in ('setup', 'tui'):
            from .tui import CustodianApp
            CustodianApp(args.state_dir, force_setup=args.command == 'setup').run()
            return _offer_dashboard_login(args.state_dir)
        if args.command == 'service':
            from . import service
            if args.action == 'install':
                result = service.install_service(args.state_dir, Path(sys.executable), enable=args.enable)
            else:
                result = getattr(service, {'start': 'start_service', 'status': 'service_status', 'stop': 'stop_service', 'uninstall': 'uninstall_service'}[args.action])()
        elif args.command == 'updates':
            from . import updates
            if args.updates_action == 'security-plan':
                result = updates.plan_security_updates(args.security_enabled)
            elif args.updates_action == 'security-apply':
                if os.getuid() != 0 or os.geteuid() != 0:
                    result = {'status': 'denied', 'changed': False, 'error': 'Requires real and effective UID 0 (root)'}
                elif not _is_root_owned_install():
                    result = {'status': 'denied', 'changed': False, 'error': 'Requires a root-owned, non-writable installation'}
                elif not (sys.stdin.isatty() and sys.stdout.isatty()):
                    result = {'status': 'denied', 'changed': False, 'error': 'Interactive terminal required for security-apply confirmation'}
                else:
                    if args.security_enabled is not None:
                        plan = updates.plan_security_updates(args.security_enabled)
                    else:
                        plan = updates.plan_security_updates(True)
                        if plan.get('plan_id') != args.plan_id:
                            alt = updates.plan_security_updates(False)
                            if alt.get('plan_id') == args.plan_id:
                                plan = alt
                    if plan.get('status') != 'ready' or plan.get('plan_id') != args.plan_id:
                        result = {'status': 'stale', 'changed': False, 'error': 'Recomputed plan_id does not match --plan-id; preview a fresh plan'}
                    else:
                        approval = input(f"Type 'APPLY SECURITY POLICY {args.plan_id}' to confirm: ").strip()
                        if approval != 'APPLY SECURITY POLICY ' + args.plan_id:
                            result = {'status': 'denied', 'changed': False, 'error': 'Exact interactive terminal confirmation required'}
                        else:
                            result = updates.apply_security_update_policy(plan, approval)
            else:
                result = updates.check_updates()
        else:
            from .engine import Engine
            engine = Engine(args.state_dir)
            if args.command == 'dashboard':
                from .web import run_dashboard
                run_dashboard(engine, port=args.port)
                return 0
            if args.command == 'monitor':
                from .monitor import run_monitor
                run_monitor(engine, args.state_dir, once=args.once)
                return 0
            result = getattr(engine, args.command)()
        print(json.dumps(result, indent=2, ensure_ascii=True))
        if isinstance(result, dict) and (result.get('ok') is False or result.get('status') not in (None, 'ok', 'ready', 'applied')):
            return 1
        return 0
    except KeyboardInterrupt:
        return 130
    except (ValueError, OSError, RuntimeError, ImportError) as exc:
        print(f'Custodian: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
