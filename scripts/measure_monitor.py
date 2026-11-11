"""Reproducible fixture-only monitor measurement; never scans real profiles."""
import argparse
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import time
from custodian.engine import Engine


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--seconds', type=int, default=15)
    args = parser.parse_args()
    if not 10 <= args.seconds <= 120:
        parser.error('seconds must be 10..120')
    scratch = os.environ.get('TMPDIR')
    if not scratch:
        parser.error('Set TMPDIR to an approved scratch directory')
    with tempfile.TemporaryDirectory(prefix='custodian-perf-', dir=scratch) as temp:
        root = Path(temp)
        scope = root / 'scope'
        scope.mkdir()
        for index in range(2000):
            (scope / f'fixture-{index:04}.py').write_text('#' + 'x' * 1023)
        state = root / 'state'
        engine = Engine(state)
        engine.setup({'watched_paths': [str(scope)], 'max_files': 10000, 'interval_seconds': 300})
        start = time.monotonic()
        baseline = engine.scan()
        baseline_seconds = time.monotonic() - start
        command = [sys.executable, '-m', 'custodian.cli', '--state-dir', str(state), 'monitor']
        child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if child.poll() is not None:
                    raise RuntimeError('Monitor exited during startup: ' + child.stderr.read().decode()[:300])
                path = state / 'monitor.json'
                if path.exists() and json.loads(path.read_text()).get('last_result'):
                    break
                time.sleep(0.1)
            else:
                raise RuntimeError('Monitor did not complete startup cycle')
            def sample():
                fields = Path(f'/proc/{child.pid}/stat').read_text().split()
                ticks = int(fields[13]) + int(fields[14])
                rss = int(Path(f'/proc/{child.pid}/statm').read_text().split()[1]) * os.sysconf('SC_PAGE_SIZE')
                return time.monotonic(), ticks, rss
            before = sample()
            time.sleep(args.seconds)
            after = sample()
            cpu = (after[1] - before[1]) / os.sysconf('SC_CLK_TCK') / (after[0] - before[0]) * 100
            status = engine.status()
            memory_mib = after[2] / (1024 * 1024)
            report = {'platform': platform.system(), 'architecture': platform.machine(),
                'hardware': Path('/proc/device-tree/model').read_text().rstrip('\x00') if Path('/proc/device-tree/model').exists() else 'not available',
                'python': platform.python_version(), 'fixture_files': 2000, 'fixture_extension': '.py', 'integrity_hash_candidates': 2000, 'bytes_per_file': 1024,
                'reconcile_interval_seconds': 300, 'observation_seconds': round(after[0] - before[0], 3),
                'baseline_scan_seconds': round(baseline_seconds, 4), 'baseline_complete': baseline['complete'],
                'baseline_files_checked': baseline['files_checked'], 'monitoring_verified': status['monitoring'],
                'idle_cpu_percent_one_core': round(cpu, 4), 'steady_rss_mib': round(memory_mib, 3),
                'monitor_targets_met': cpu < 1 and memory_mib <= 100,
                'limitations': ['Synthetic local workload only', 'Not a boot/reboot test', 'Dashboard/browser not included', 'No hostile same-user tamper-resistance claim']}
        finally:
            child.terminate()
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, indent=2))
        return 0 if report['monitor_targets_met'] and report['baseline_complete'] and report['monitoring_verified'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
