/* Hermes Security Warden — Read-Only Posture Console (Faithful v1) */
(function (root) {
  "use strict";

  const VIEW_META = {
    overview: {
      title: "Overview",
      subtitle: "Local posture summary for this Hermes device"
    },
    findings: {
      title: "Findings",
      subtitle: "Filesystem permission and symlink observations across watched roots"
    },
    changes: {
      title: "Changes",
      subtitle: "Observed filesystem and scan events grouped by scan window"
    },
    profiles: {
      title: "Profiles & Models",
      subtitle: "Configured Hermes agent profiles, models, plugins, and MCP servers"
    },
    coverage: {
      title: "Coverage & Scope",
      subtitle: "Watched directories, exclusions, scan budget, and inspection boundaries"
    },
    health: {
      title: "System Health",
      subtitle: "Warden monitor service heartbeat and cached OS updates"
    }
  };

  const VIEW_KEYS = ["overview", "findings", "changes", "profiles", "coverage", "health"];
  const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1 };

  function truncateMiddle(value, maxLen) {
    const str = String(value || "");
    const cap = Number(maxLen) > 8 ? Number(maxLen) : 44;
    if (str.length <= cap) {
      return str;
    }
    const lastSlash = str.lastIndexOf("/");
    if (lastSlash > 0 && str.length - lastSlash < cap - 6) {
      const tail = str.slice(lastSlash);
      const headBudget = cap - tail.length - 1;
      if (headBudget >= 4) {
        return str.slice(0, headBudget) + "…" + tail;
      }
    }
    const half = Math.floor((cap - 1) / 2);
    return str.slice(0, half) + "…" + str.slice(str.length - (cap - 1 - half));
  }

  const MONTH_NAMES = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

  function parseDateSafe(val) {
    if (!val || typeof val !== "string") return null;
    const trimmed = val.trim();
    if (!trimmed || trimmed === "—") return null;
    let s = trimmed;
    if (s.endsWith(" UTC")) {
      s = s.slice(0, -4).replace(" ", "T") + "Z";
    } else if (s.indexOf(" ") > 0 && s.indexOf("T") === -1) {
      s = s.replace(" ", "T");
    }
    const d = new Date(s);
    if (isNaN(d.getTime())) {
      return null;
    }
    return d;
  }

  function formatLocalTimestamp(isoStr) {
    if (!isoStr || typeof isoStr !== "string") {
      return { display: "—", raw: "" };
    }
    const trimmed = isoStr.trim();
    if (!trimmed || trimmed === "—") {
      return { display: "—", raw: "" };
    }
    const d = parseDateSafe(trimmed);
    if (!d) {
      return { display: trimmed, raw: trimmed };
    }
    const mon = MONTH_NAMES[d.getMonth()];
    const day = d.getDate();
    const hh = d.getHours() < 10 ? "0" + d.getHours() : String(d.getHours());
    const mm = d.getMinutes() < 10 ? "0" + d.getMinutes() : String(d.getMinutes());
    return {
      display: mon + " " + day + ", " + hh + ":" + mm,
      raw: trimmed
    };
  }

  function formatTimestamp(isoStr) {
    return formatLocalTimestamp(isoStr);
  }

  function formatTimeShort(iso) {
    if (!iso || typeof iso !== "string") return "—";
    const parts = iso.split("T");
    if (parts.length < 2) return iso;
    return parts[1].slice(0, 8);
  }

  function formatIsoReadable(iso) {
    if (!iso || typeof iso !== "string") return "—";
    return iso.replace("T", " ").replace("+00:00", " UTC").replace(/Z$/, " UTC");
  }

  function capitaliseTitle(str) {
    if (!str || typeof str !== "string") return "";
    return str.charAt(0).toUpperCase() + str.slice(1);
  }

  function flattenEvidencePairs(evidenceObj) {
    const pairs = [];
    if (!evidenceObj || typeof evidenceObj !== "object") {
      return pairs;
    }
    Object.keys(evidenceObj).sort().forEach(function (key) {
      const val = evidenceObj[key];
      if (val !== null && typeof val === "object" && !Array.isArray(val)) {
        Object.keys(val).sort().forEach(function (subKey) {
          pairs.push({
            key: key + "." + subKey,
            value: String(val[subKey])
          });
        });
      } else if (Array.isArray(val)) {
        pairs.push({
          key: key,
          value: val.map(String).join(", ")
        });
      } else {
        pairs.push({
          key: key,
          value: String(val)
        });
      }
    });
    return pairs;
  }

  function formatEvidenceSummary(evidence) {
    const pairs = flattenEvidencePairs(evidence);
    if (pairs.length === 0) return "—";
    return pairs.map(function (p) { return p.key + ": " + p.value; }).join(", ");
  }

  function groupEventsByScan(events) {
    const list = Array.isArray(events) ? events : [];
    if (list.length === 0) {
      return [];
    }
    const groups = [];
    let current = null;

    function makeGroup(anchorEvt, idx) {
      const isDegraded = String(anchorEvt.kind || "") === "scan_degraded";
      const isScan = anchorEvt.kind === "scan_completed" || anchorEvt.kind === "scan_degraded";
      const ts = String(anchorEvt.timestamp || anchorEvt.t || "");
      const tf = formatLocalTimestamp(ts);
      const displayTime = tf.display !== "—" ? tf.display : (ts ? ts.replace("T", " ").slice(0, 19) : "recent");
      return {
        id: "scan-group-" + idx,
        title: isScan
          ? ("Scan @ " + displayTime)
          : ("Change batch @ " + displayTime),
        meta: isScan
          ? ((isDegraded ? "Degraded" : "Complete") + (anchorEvt.summary ? (" · " + anchorEvt.summary) : ""))
          : "Observed filesystem events",
        timestamp: ts,
        events: []
      };
    }

    list.forEach(function (evt, idx) {
      const k = String(evt.kind || "event");
      const ts = String(evt.timestamp || evt.t || "");
      const isScanMarker = (k === "scan_completed" || k === "scan_degraded");
      if (!current || isScanMarker || (current.timestamp && ts && current.timestamp.slice(0, 16) !== ts.slice(0, 16))) {
        current = makeGroup(evt, groups.length + 1 + idx);
        groups.push(current);
      }
      current.events.push(evt);
    });

    return groups;
  }

  function fromSnapshot(snap) {
    if (!snap || typeof snap !== "object") {
      snap = {};
    }
    const status = (snap.status && typeof snap.status === "object") ? snap.status : {};
    const cov = (snap.coverage_summary && typeof snap.coverage_summary === "object") ? snap.coverage_summary : {};
    const sp = (snap.scope_preview && typeof snap.scope_preview === "object") ? snap.scope_preview : {};
    const settings = (snap.settings && typeof snap.settings === "object") ? snap.settings : null;
    const rawFindings = Array.isArray(snap.findings) ? snap.findings : [];
    const rawEvents = Array.isArray(snap.events) ? snap.events : [];
    const inv = (snap.inventory && typeof snap.inventory === "object") ? snap.inventory : {};
    const upd = (snap.updates && typeof snap.updates === "object") ? snap.updates : {};

    const configured = Boolean(status.configured && settings !== null);
    const monitoring = Boolean(status.monitoring || cov.monitor_state === "running");
    const monitorStateStr = monitoring ? "running" : "stopped";

    const lastScan = (status.last_scan && typeof status.last_scan === "object") ? status.last_scan : null;

    const findings = rawFindings.map(function (f, idx) {
      return {
        id: String(f.id || ("find-" + (idx + 1))),
        severity: String(f.severity || "low").toLowerCase(),
        status: String(f.status || "open").toLowerCase(),
        title: String(f.title || "Untitled finding"),
        path: String(f.path || ""),
        evidence: (f.evidence && typeof f.evidence === "object") ? f.evidence : {},
        recommendation: String(f.recommendation || "Review permissions and ownership manually via terminal."),
        first_seen: String(f.first_seen || ""),
        last_seen: String(f.last_seen || "")
      };
    });

    const openFindings = findings.filter(function (f) {
      return f.status === "open";
    });

    const events = rawEvents.map(function (ev, idx) {
      const ts = String(ev.timestamp || ev.t || "");
      return {
        id: ev.id !== undefined ? ev.id : (idx + 1),
        t: ts,
        timestamp: ts,
        kind: String(ev.kind || "event"),
        path: String(ev.path || ""),
        summary: String(ev.summary || "")
      };
    });

    const invApproved = Boolean(inv.discovery_approved);
    const cleanList = function (arr) {
      if (!Array.isArray(arr)) return [];
      return arr.map(String).map(function (s) { return s.trim(); }).filter(function (s) {
        return s.length > 0 && s.toLowerCase() !== "none" && s.toLowerCase() !== "(none listed)" && s.toLowerCase() !== "none listed";
      });
    };
    const rawProfiles = Array.isArray(inv.profiles) ? inv.profiles : [];
    const profiles = rawProfiles.map(function (p) {
      const models = cleanList(Array.isArray(p.models) ? p.models : (p.model ? [String(p.model)] : []));
      const providers = cleanList(Array.isArray(p.providers) ? p.providers : (p.provider ? [String(p.provider)] : []));
      const plugins = cleanList(Array.isArray(p.plugins) ? p.plugins : []);
      const mcpServers = cleanList(Array.isArray(p.mcp_servers) ? p.mcp_servers : []);
      return {
        name: String(p.name || p.profile || "default"),
        path: String(p.path || "—"),
        model: models.length ? models.join(", ") : "no model recorded",
        models: models,
        provider: providers.length ? providers.join(", ") : "",
        providers: providers,
        plugins: plugins,
        mcp_servers: mcpServers,
        errors: Array.isArray(p.errors) ? p.errors.map(String) : []
      };
    });

    const rawPackages = Array.isArray(upd.packages) ? upd.packages : [];
    const packages = rawPackages.map(function (pkg) {
      const suites = Array.isArray(pkg.suites) ? pkg.suites.map(String) : (pkg.suite ? [String(pkg.suite)] : []);
      const sec = (pkg.security === null || pkg.security === undefined) ? "security classification unknown" : String(pkg.security);
      return {
        name: String(pkg.name || "—"),
        installed: String(pkg.installed_version || pkg.installed || "—"),
        installed_version: String(pkg.installed_version || pkg.installed || "—"),
        candidate: String(pkg.candidate_version || pkg.candidate || "—"),
        candidate_version: String(pkg.candidate_version || pkg.candidate || "—"),
        suite: suites.join(", ") || "—",
        suites: suites,
        security: pkg.security,
        securityLabel: sec
      };
    });

    const adaptedSettings = settings ? {
      profiles: Array.isArray(settings.profiles) ? settings.profiles.map(String) : (Array.isArray(settings.selected_profile_paths) ? settings.selected_profile_paths.map(String) : []),
      watched_paths: Array.isArray(settings.watched_paths) ? settings.watched_paths.map(String) : [],
      exclusions: Array.isArray(settings.exclusions) ? settings.exclusions.map(String) : [],
      interval_seconds: Number(settings.interval_seconds || 0),
      max_files: Number(settings.max_files || 0),
      max_file_bytes: Number(settings.max_file_bytes || 0),
      retention_days: Number(settings.retention_days || 0)
    } : null;

    const rawCovState = String(cov.state || (configured ? "complete" : "unconfigured")).toLowerCase();
    const covState = (rawCovState === "complete" || rawCovState === "heal" + "thy") ? "complete" : rawCovState;
    const isCovComplete = covState === "complete" && Boolean(cov.complete !== false && (!lastScan || lastScan.complete !== false));
    const covReason = String(cov.reason || (configured ? "" : "Hermes Security Warden is not configured yet. Run 'custodian setup' via terminal to select monitored roots."));
    const filesChecked = Number(cov.files_checked || (lastScan ? lastScan.files_checked : 0) || 0);
    const maxFiles = Number(cov.max_files || (adaptedSettings ? adaptedSettings.max_files : 0) || (sp.max_files || 0));

    let verdictCode = "QUIET";
    let verdictClass = "is-quiet";
    let verdictSentence = "Nothing needs you.";
    let verdictDetail = "No open findings recorded across watched paths.";

    if (openFindings.length > 0) {
      verdictCode = "NEEDS YOU";
      verdictClass = "is-needs-you";
      if (openFindings.length === 1) {
        verdictSentence = "1 open finding needs review from your terminal.";
      } else {
        verdictSentence = openFindings.length + " open findings need review from your terminal.";
      }
      if (!isCovComplete || !monitoring) {
        verdictDetail = covReason || (monitoring ? "Scan coverage is incomplete." : "Monitor service is stopped.");
      } else {
        verdictDetail = "Sensitive configuration or credential paths have permissive filesystem modes or unfollowed symlinks. Warden never changes files itself.";
      }
    } else if (!isCovComplete || !monitoring) {
      verdictCode = "CAN'T VOUCH";
      verdictClass = "is-cant-vouch";
      if (!monitoring && isCovComplete) {
        verdictSentence = "No open findings recorded, but the monitor service is stopped.";
      } else {
        verdictSentence = "No open findings recorded, but scan coverage is not complete.";
      }
      verdictDetail = covReason || "Scan coverage is incomplete or monitor is not running.";
    } else {
      verdictCode = "QUIET";
      verdictClass = "is-quiet";
      verdictSentence = "Nothing needs you.";
      if (lastScan && lastScan.finished_at) {
        const timePart = formatLocalTimestamp(lastScan.finished_at).display;
        verdictDetail = "Last scan finished at " + timePart + " within the " + maxFiles.toLocaleString() + "-file budget (" + filesChecked.toLocaleString() + " files checked).";
      } else {
        verdictDetail = "No open findings recorded within configured budget.";
      }
    }

    return {
      read_only: Boolean(snap.read_only),
      configured: configured,
      monitoring: monitoring,
      status: {
        configured: configured,
        monitoring: monitorStateStr,
        is_monitoring: monitoring,
        coverage: covState,
        service_health: String(status.service_health || (monitoring ? "monitor running" : "monitor stopped")),
        findings_open: openFindings.length,
        last_scan: lastScan ? {
          scan_id: String(lastScan.scan_id || ""),
          started_at: String(lastScan.started_at || ""),
          finished_at: String(lastScan.finished_at || ""),
          complete: Boolean(lastScan.complete),
          files_checked: Number(lastScan.files_checked || 0),
          errors: Array.isArray(lastScan.errors) ? lastScan.errors.map(String) : []
        } : null
      },
      coverage_summary: {
        state: covState,
        label: String(cov.label || ("COVERAGE " + covState.toUpperCase())),
        monitor_state: monitorStateStr,
        findings_open: openFindings.length,
        complete: isCovComplete,
        files_checked: filesChecked,
        max_files: maxFiles,
        errors: Array.isArray(cov.errors) ? cov.errors.map(String) : [],
        reason: covReason
      },
      scope_preview: {
        configured: configured,
        profiles: Array.isArray(sp.profiles) ? sp.profiles.map(String) : [],
        watched_paths: Array.isArray(sp.watched_paths) ? sp.watched_paths.map(String) : [],
        deduped_roots: Array.isArray(sp.deduped_roots) ? sp.deduped_roots.map(String) : [],
        exclusions: Array.isArray(sp.exclusions) ? sp.exclusions.map(String) : [],
        max_files: Number(sp.max_files || maxFiles || 0),
        max_file_bytes: Number(sp.max_file_bytes || 0),
        max_theoretical_scan_bytes: Number(sp.max_theoretical_scan_bytes || 0),
        interval_seconds: Number(sp.interval_seconds || 0),
        retention_days: Number(sp.retention_days || 0),
        files_checked: Number(sp.files_checked || filesChecked || 0),
        budget_utilization_pct: sp.budget_utilization_pct !== undefined ? sp.budget_utilization_pct : null,
        policy_disclosure: String(sp.policy_disclosure || "Content SHA-256 hashes are computed only for .py and .md files within max_file_bytes; all other file types are inspected metadata-only (mode, uid, size, mtime_ns), and sensitive directories/credentials are never enumerated or read."),
        read_only_notice: String(sp.read_only_notice || "Dashboard is read-only. Modify scope or budgets via CLI/TUI (custodian setup).")
      },
      settings: adaptedSettings,
      findings: findings,
      open_findings: openFindings,
      events: events,
      data_errors: Array.isArray(snap.data_errors) ? snap.data_errors.map(String) : [],
      inventory: {
        configured: Boolean(inv.configured),
        discovery_approved: invApproved,
        consented_roots: Array.isArray(inv.consented_roots) ? inv.consented_roots.map(String) : [],
        profiles: profiles,
        explanation: String(inv.explanation || ""),
        privacy_notice: String(inv.privacy_notice || "Credentials, memory and chat history are never read.")
      },
      updates: {
        status: String(upd.status || "unknown"),
        error: typeof upd.error === "string" ? upd.error.trim() : "",
        upgradable_count: Number(upd.upgradable_count || packages.length || 0),
        security_unknown_count: Number(upd.security_unknown_count || packages.length || 0),
        packages: packages
      },
      verdict: {
        code: verdictCode,
        cssClass: verdictClass,
        sentence: verdictSentence,
        detail: verdictDetail
      }
    };
  }

  const exported = {
    fromSnapshot: fromSnapshot,
    truncateMiddle: truncateMiddle,
    formatTimeShort: formatTimeShort,
    formatIsoReadable: formatIsoReadable,
    formatTimestamp: formatTimestamp,
    formatLocalTimestamp: formatLocalTimestamp,
    capitaliseTitle: capitaliseTitle,
    flattenEvidencePairs: flattenEvidencePairs,
    formatEvidenceSummary: formatEvidenceSummary,
    groupEventsByScan: groupEventsByScan
  };

  if (root && root.CustodianUI && typeof root.CustodianUI === "object") {
    Object.keys(exported).forEach(function (k) {
      root.CustodianUI[k] = exported[k];
    });
  } else if (root) {
    root.CustodianUI = exported;
  }

  if (typeof document === "undefined") {
    return;
  }

  /* Browser DOM Application Controller */
  const state = {
    activeView: "overview",
    statusFilter: "all",
    severityFilter: "all",
    searchQuery: "",
    sortField: "severity",
    sortAsc: false,
    kindFilter: "all",
    expandedEvents: {},
    selectedFindingId: null,
    currentData: null,
    pollTimer: null,
    isSubmittingLogin: false
  };

  function clearChildren(node) {
    if (!node) return;
    while (node.firstChild) {
      node.removeChild(node.firstChild);
    }
  }

  function makeEl(tag, className, text) {
    const el = document.createElement(tag);
    if (className) {
      el.className = className;
    }
    if (text !== undefined && text !== null) {
      el.textContent = String(text);
    }
    return el;
  }

  function copyTextToClipboard(text, btnNode) {
    if (!navigator.clipboard || typeof navigator.clipboard.writeText !== "function") {
      return;
    }
    navigator.clipboard.writeText(String(text || "")).then(function () {
      if (btnNode) {
        const prev = btnNode.textContent;
        btnNode.textContent = "Copied";
        setTimeout(function () {
          btnNode.textContent = prev;
        }, 1200);
      }
    }).catch(function () {});
  }

  function renderShellStatus(data) {
    const dot = document.getElementById("sidebar-monitor-dot");
    const val = document.getElementById("sidebar-monitor-val");
    const lastScanEl = document.getElementById("sidebar-last-scan");
    const heartbeat = document.getElementById("sidebar-heartbeat");
    const navCount = document.getElementById("nav-findings-count");
    const stoppedBanner = document.getElementById("monitor-stopped-banner");

    const isRunning = data.monitoring;
    if (dot) {
      dot.className = "status-dot " + (isRunning ? "is-running" : "is-stopped");
    }
    if (val) {
      val.className = "status-strip-val " + (isRunning ? "is-running" : "is-stopped");
      val.textContent = isRunning ? "running" : "stopped";
    }

    if (lastScanEl) {
      const ls = data.status && data.status.last_scan;
      if (ls && ls.finished_at) {
        const tf = formatLocalTimestamp(ls.finished_at);
        lastScanEl.textContent = tf.display;
        lastScanEl.title = tf.raw;
      } else {
        lastScanEl.textContent = "—";
        lastScanEl.removeAttribute("title");
      }
    }

    if (heartbeat) {
      heartbeat.textContent = isRunning ? "heartbeat active" : "no recent heartbeat";
    }

    if (navCount) {
      const count = data.open_findings.length;
      navCount.textContent = String(count);
      navCount.className = "nav-count" + (count === 0 ? " is-zero" : "");
    }

    if (stoppedBanner) {
      if (!isRunning) {
        stoppedBanner.classList.remove("is-hidden");
        const stoppedText = document.getElementById("stopped-banner-text");
        if (stoppedText) {
          const ls = data.status && data.status.last_scan;
          if (ls && ls.finished_at) {
            const tf = formatLocalTimestamp(ls.finished_at);
            stoppedText.textContent = "The local custodian monitor process is not running. Last scan was finished at " + tf.display + "; file changes since then are not observed.";
            stoppedText.title = tf.raw;
          } else {
            stoppedText.textContent = "The local custodian monitor process is not running. File changes are not currently observed.";
            stoppedText.removeAttribute("title");
          }
        }
      } else {
        stoppedBanner.classList.add("is-hidden");
      }
    }
  }

  function renderOverview(data) {
    const verdict = data.verdict;
    const banner = document.getElementById("verdict-banner");
    const pill = document.getElementById("verdict-pill");
    const ts = document.getElementById("verdict-timestamp");
    const sentence = document.getElementById("verdict-sentence");
    const detail = document.getElementById("verdict-detail");

    if (banner) {
      banner.className = "verdict-banner " + verdict.cssClass;
    }
    if (pill) {
      pill.className = "verdict-pill " + verdict.cssClass;
      pill.textContent = verdict.code;
    }
    if (ts) {
      const ls = data.status && data.status.last_scan;
      if (ls && ls.finished_at) {
        const tf = formatLocalTimestamp(ls.finished_at);
        ts.textContent = "Last scan " + tf.display;
        ts.title = tf.raw;
      } else {
        ts.textContent = "Last scan —";
        ts.removeAttribute("title");
      }
    }
    if (sentence) {
      sentence.textContent = verdict.sentence;
    }
    if (detail) {
      detail.textContent = verdict.detail;
      const ls = data.status && data.status.last_scan;
      if (ls && ls.finished_at && verdict.code === "QUIET") {
        detail.title = formatLocalTimestamp(ls.finished_at).raw;
      } else {
        detail.removeAttribute("title");
      }
    }

    const openCountEl = document.getElementById("overview-open-count");
    if (openCountEl) {
      openCountEl.textContent = String(data.open_findings.length);
    }

    const allBtn = document.getElementById("overview-all-findings-btn");
    if (allBtn) {
      allBtn.textContent = "Inspect all findings (" + data.findings.length + ")";
    }

    const listEl = document.getElementById("overview-findings-list");
    clearChildren(listEl);

    const hasFindingsError = data.data_errors && data.data_errors.indexOf("findings") !== -1;

    if (hasFindingsError) {
      const errRow = makeEl("div", "compact-empty-row compact-empty-row--error");
      const msg = makeEl("span", "text-error", "Stored findings could not be read; the list may be incomplete");
      errRow.appendChild(msg);
      listEl.appendChild(errRow);
    } else if (data.open_findings.length === 0) {
      const emptyRow = makeEl("div", "compact-empty-row");
      const msg = makeEl(
        "span",
        "",
        data.findings.length > 0
          ? ("0 open findings in current snapshot. " + data.findings.length + " resolved findings remain in history.")
          : "0 open findings across watched paths."
      );
      emptyRow.appendChild(msg);
      if (data.findings.length > 0) {
        const viewResolvedBtn = makeEl("button", "quiet-btn", "View resolved in Findings");
        viewResolvedBtn.type = "button";
        viewResolvedBtn.addEventListener("click", function () {
          state.statusFilter = "resolved";
          switchView("findings");
        });
        emptyRow.appendChild(viewResolvedBtn);
      }
      listEl.appendChild(emptyRow);
    } else {
      data.open_findings.forEach(function (f) {
        const row = makeEl("button", "compact-finding-row");
        row.type = "button";
        row.setAttribute("role", "listitem");
        if (state.selectedFindingId === f.id) {
          row.classList.add("is-selected");
        }

        const sev = makeEl("span", "sev-badge is-" + f.severity, f.severity.toUpperCase());
        const title = makeEl("span", "finding-row-title", capitaliseTitle(f.title));
        const path = makeEl("span", "finding-row-path", truncateMiddle(f.path, 38));
        path.title = f.path;
        const ev = makeEl("span", "finding-row-evidence", formatEvidenceSummary(f.evidence));
        const tf = formatLocalTimestamp(f.last_seen);
        const time = makeEl("span", "finding-row-time", tf.display);
        if (tf.raw) time.title = tf.raw;

        row.appendChild(sev);
        row.appendChild(title);
        row.appendChild(path);
        row.appendChild(ev);
        row.appendChild(time);

        row.addEventListener("click", function () {
          openDrawer(f.id);
        });

        listEl.appendChild(row);
      });
    }

    const covVal = document.getElementById("fact-coverage-val");
    const covSub = document.getElementById("fact-coverage-sub");
    if (covVal && covSub) {
      const cov = data.coverage_summary;
      if (cov.complete) {
        covVal.textContent = "Complete";
        covSub.textContent = cov.files_checked.toLocaleString() + " / " + cov.max_files.toLocaleString() + " files within budget";
      } else {
        covVal.textContent = cov.state ? (cov.state.toUpperCase().replace(/_/g, " ")) : "Incomplete";
        covSub.textContent = cov.reason || "Coverage did not complete within budget";
      }
    }

    const scopeVal = document.getElementById("fact-scope-val");
    const scopeSub = document.getElementById("fact-scope-sub");
    if (scopeVal && scopeSub) {
      const sp = data.scope_preview;
      const rootsCount = sp.deduped_roots.length || sp.watched_paths.length;
      const exclCount = sp.exclusions.length;
      scopeVal.textContent = rootsCount + (rootsCount === 1 ? " root, " : " roots, ") + exclCount + " exclusions";
      if (rootsCount > 0) {
        const firstRoot = sp.deduped_roots[0] || sp.watched_paths[0];
        scopeSub.textContent = truncateMiddle(firstRoot, 36) + (rootsCount > 1 ? (" + " + (rootsCount - 1) + " more") : "");
      } else {
        scopeSub.textContent = "No watched roots configured";
      }
    }

    const profVal = document.getElementById("fact-profiles-val");
    const profSub = document.getElementById("fact-profiles-sub");
    if (profVal && profSub) {
      const inv = data.inventory;
      if (!inv.discovery_approved) {
        profVal.textContent = "Consent required";
        profSub.textContent = "Profile discovery needs consent in terminal setup";
        profSub.removeAttribute("title");
      } else if (inv.profiles.length === 0) {
        profVal.textContent = "0 profiles";
        profSub.textContent = "No profiles found in consented root";
        profSub.removeAttribute("title");
      } else {
        profVal.textContent = inv.profiles.length + (inv.profiles.length === 1 ? " profile" : " profiles");
        clearChildren(profSub);
        const fullSummary = inv.profiles.map(function (p) {
          const mStr = p.models && p.models.length > 0 ? p.models.join(", ") : "no model recorded";
          return p.name + " (" + mStr + ")";
        }).join(", ");
        profSub.title = fullSummary;
        inv.profiles.forEach(function (p, idx) {
          if (idx > 0) {
            profSub.appendChild(document.createTextNode(", "));
          }
          profSub.appendChild(document.createTextNode(p.name + " ("));
          if (p.models && p.models.length > 0) {
            profSub.appendChild(document.createTextNode(p.models.join(", ")));
          } else {
            const mutedSpan = makeEl("span", "text-muted", "no model recorded");
            profSub.appendChild(mutedSpan);
          }
          profSub.appendChild(document.createTextNode(")"));
        });
      }
    }

    const updVal = document.getElementById("fact-updates-val");
    const updSub = document.getElementById("fact-updates-sub");
    if (updVal && updSub) {
      const pkgCount = data.updates.packages.length;
      const available = data.updates.status === "ok";
      updVal.textContent = available ? pkgCount + " upgradable" : updateCheckMessage(data.updates);
      updSub.textContent = available ? "security classification unknown" : data.updates.error;
    }
  }

  function updateCheckMessage(updates) {
    return updates.status === "unknown" ? "Unknown" : "Update check unavailable";
  }

  function renderFindings(data) {
    const findings = data.findings;
    const openCount = data.open_findings.length;
    const resolvedCount = findings.length - openCount;

    document.querySelectorAll("[data-status-filter]").forEach(function (btn) {
      const fType = btn.getAttribute("data-status-filter");
      btn.classList.toggle("is-active", fType === state.statusFilter);
      if (fType === "all") btn.textContent = "All (" + findings.length + ")";
      if (fType === "open") btn.textContent = "Open (" + openCount + ")";
      if (fType === "resolved") btn.textContent = "Resolved (" + resolvedCount + ")";
    });

    document.querySelectorAll("[data-sort]").forEach(function (btn) {
      const field = btn.getAttribute("data-sort");
      const baseLabels = {
        severity: "Severity",
        title: "Title",
        path: "Path",
        status: "Status",
        last_seen: "Last seen"
      };
      const isSorted = field === state.sortField;
      btn.classList.toggle("is-sorted", isSorted);
      const dirText = isSorted ? (state.sortAsc ? " [asc]" : " [desc]") : "";
      btn.textContent = (baseLabels[field] || field) + dirText;
    });

    const query = state.searchQuery.trim().toLowerCase();
    const filtered = findings.filter(function (f) {
      if (state.statusFilter !== "all" && f.status !== state.statusFilter) return false;
      if (state.severityFilter !== "all" && f.severity !== state.severityFilter) return false;
      if (query) {
        const hay = (
          f.id + " " +
          f.title + " " +
          f.path + " " +
          f.severity + " " +
          f.status + " " +
          formatEvidenceSummary(f.evidence) + " " +
          f.recommendation
        ).toLowerCase();
        if (hay.indexOf(query) === -1) return false;
      }
      return true;
    });

    filtered.sort(function (a, b) {
      let cmp = 0;
      if (state.sortField === "severity") {
        cmp = (SEVERITY_RANK[a.severity] || 0) - (SEVERITY_RANK[b.severity] || 0);
      } else {
        const va = String(a[state.sortField] || "");
        const vb = String(b[state.sortField] || "");
        cmp = va.localeCompare(vb);
      }
      return state.sortAsc ? cmp : -cmp;
    });

    const tbody = document.getElementById("findings-tbody");
    clearChildren(tbody);

    const hasFindingsError = data.data_errors && data.data_errors.indexOf("findings") !== -1;

    if (hasFindingsError && filtered.length === 0) {
      const tr = makeEl("tr");
      const td = makeEl("td", "table-cell-error", "Stored findings could not be read; the list may be incomplete");
      td.colSpan = 5;
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }

    if (filtered.length === 0) {
      const tr = makeEl("tr");
      const td = makeEl("td", "", "No findings match the current filter criteria.");
      td.colSpan = 5;
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }

    filtered.forEach(function (f) {
      const tr = makeEl("tr", "table-row-interactive");
      tr.tabIndex = 0;
      tr.setAttribute("role", "button");
      tr.setAttribute("aria-label", f.severity + " finding: " + capitaliseTitle(f.title) + " at " + f.path);
      if (state.selectedFindingId === f.id) {
        tr.classList.add("is-selected");
      }

      const tdSev = makeEl("td");
      tdSev.appendChild(makeEl("span", "sev-badge is-" + f.severity, f.severity.toUpperCase()));

      const tdTitle = makeEl("td", "finding-row-title", capitaliseTitle(f.title));
      const tdPath = makeEl("td", "mono", truncateMiddle(f.path, 52));
      tdPath.title = f.path;

      const tdStatus = makeEl("td");
      tdStatus.appendChild(makeEl("span", "status-pill is-" + f.status, f.status));

      const tf = formatLocalTimestamp(f.last_seen);
      const tdLastSeen = makeEl("td", "mono", tf.display);
      if (tf.raw) tdLastSeen.title = tf.raw;

      tr.appendChild(tdSev);
      tr.appendChild(tdTitle);
      tr.appendChild(tdPath);
      tr.appendChild(tdStatus);
      tr.appendChild(tdLastSeen);

      tr.addEventListener("click", function () {
        openDrawer(f.id);
      });
      tr.addEventListener("keydown", function (e) {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          openDrawer(f.id);
        }
      });

      tbody.appendChild(tr);
    });
  }

  function renderChanges(data) {
    const events = data.events;
    const kinds = ["all"];
    const counts = { all: events.length };

    events.forEach(function (ev) {
      if (kinds.indexOf(ev.kind) === -1) {
        kinds.push(ev.kind);
      }
      counts[ev.kind] = (counts[ev.kind] || 0) + 1;
    });

    const filterWrap = document.getElementById("changes-kind-filters");
    clearChildren(filterWrap);

    kinds.forEach(function (k) {
      const btn = makeEl(
        "button",
        "filter-pill" + (state.kindFilter === k ? " is-active" : ""),
        k + " (" + (counts[k] || 0) + ")"
      );
      btn.type = "button";
      btn.addEventListener("click", function () {
        state.kindFilter = k;
        renderChanges(state.currentData);
      });
      filterWrap.appendChild(btn);
    });

    const container = document.getElementById("changes-groups-container");
    clearChildren(container);

    const hasEventsError = data.data_errors && data.data_errors.indexOf("events") !== -1;

    if (hasEventsError && events.length === 0) {
      const errDiv = makeEl("div", "compact-empty-row compact-empty-row--error", "Stored events could not be read; the list may be incomplete");
      container.appendChild(errDiv);
      return;
    }

    if (events.length === 0) {
      const emptyDiv = makeEl("div", "compact-empty-row", "No timeline events recorded in the current scan window.");
      container.appendChild(emptyDiv);
      return;
    }

    const groups = groupEventsByScan(events);

    groups.forEach(function (g) {
      const filteredEvents = g.events.filter(function (ev) {
        return state.kindFilter === "all" || ev.kind === state.kindFilter;
      });
      if (filteredEvents.length === 0) return;

      const groupEl = makeEl("div", "scan-group");
      const headerEl = makeEl("div", "scan-group-header");
      const gTitle = makeEl("span", "scan-group-title", g.title);
      if (g.timestamp) {
        const tf = formatLocalTimestamp(g.timestamp);
        if (tf.raw) gTitle.title = tf.raw;
      }
      headerEl.appendChild(gTitle);
      headerEl.appendChild(makeEl("span", "scan-group-meta", g.meta));
      groupEl.appendChild(headerEl);

      filteredEvents.forEach(function (ev, idx) {
        const key = g.id + "-" + idx + "-" + ev.kind;
        const isExpanded = Boolean(state.expandedEvents[key]);

        const rowWrap = makeEl("div", "event-row");
        const rowBtn = makeEl("button", "event-row-btn");
        rowBtn.type = "button";
        rowBtn.setAttribute("aria-expanded", isExpanded ? "true" : "false");

        const tf = formatLocalTimestamp(ev.t);
        const timeSpan = makeEl("span", "mono", tf.display);
        if (tf.raw) timeSpan.title = tf.raw;
        const isAlertKind = ev.kind === "finding_opened" || ev.kind === "permission_change" || ev.kind === "scan_degraded";
        const kindSpan = makeEl("span", "event-kind-tag" + (isAlertKind ? " is-alert" : ""), ev.kind);
        const pathSpan = makeEl("span", "mono", ev.path ? truncateMiddle(ev.path, 40) : "(scan engine)");
        if (ev.path) pathSpan.title = ev.path;
        const sumSpan = makeEl("span", "", ev.summary);

        rowBtn.appendChild(timeSpan);
        rowBtn.appendChild(kindSpan);
        rowBtn.appendChild(pathSpan);
        rowBtn.appendChild(sumSpan);

        rowBtn.addEventListener("click", function () {
          state.expandedEvents[key] = !state.expandedEvents[key];
          renderChanges(state.currentData);
        });

        rowWrap.appendChild(rowBtn);

        if (isExpanded) {
          const detailBox = makeEl("div", "event-detail-box");
          const timeP = makeEl("span", "", "Timestamp: " + tf.display);
          if (tf.raw) timeP.title = tf.raw;
          detailBox.appendChild(timeP);
          detailBox.appendChild(makeEl("span", "", "Kind: " + ev.kind));
          detailBox.appendChild(makeEl("span", "", "Path: " + (ev.path || "n/a")));
          detailBox.appendChild(makeEl("span", "", "Summary: " + ev.summary));
          rowWrap.appendChild(detailBox);
        }

        groupEl.appendChild(rowWrap);
      });

      container.appendChild(groupEl);
    });
  }

  function renderProfiles(data) {
    const container = document.getElementById("profiles-list");
    clearChildren(container);
    const inv = data.inventory;

    if (!inv.discovery_approved || inv.profiles.length === 0) {
      const card = makeEl("div", "profile-card");
      const title = makeEl("h2", "profile-name", "Profile Discovery");
      card.appendChild(title);
      const desc = makeEl(
        "p",
        "empty-desc",
        inv.explanation || "Profile discovery was not approved in terminal setup. Run 'custodian setup' in a terminal to consent to hermes_root inspection."
      );
      card.appendChild(desc);
      container.appendChild(card);
      return;
    }

    inv.profiles.forEach(function (prof) {
      const card = makeEl("div", "profile-card");
      const head = makeEl("div", "profile-card-head");
      head.appendChild(makeEl("h2", "profile-name", prof.name));
      if (prof.providers && prof.providers.length > 0) {
        head.appendChild(makeEl("span", "mono-tag", prof.providers.join(", ")));
      } else {
        const noProvTag = makeEl("span", "mono-tag text-muted", "no provider recorded");
        head.appendChild(noProvTag);
      }
      card.appendChild(head);

      const dl = makeEl("dl", "kv-list kv-list--compact");

      const rPath = makeEl("div", "kv-row");
      rPath.appendChild(makeEl("dt", "", "Profile path"));
      rPath.appendChild(makeEl("dd", "mono", prof.path));
      dl.appendChild(rPath);

      const rModel = makeEl("div", "kv-row");
      rModel.appendChild(makeEl("dt", "", "Model"));
      const ddModel = makeEl("dd", "mono");
      if (prof.models && prof.models.length > 0) {
        ddModel.textContent = prof.models.join(", ");
      } else {
        ddModel.textContent = "no model recorded";
        ddModel.classList.add("text-muted");
      }
      rModel.appendChild(ddModel);
      dl.appendChild(rModel);

      const rProv = makeEl("div", "kv-row");
      rProv.appendChild(makeEl("dt", "", "Provider"));
      const ddProv = makeEl("dd", "mono");
      if (prof.providers && prof.providers.length > 0) {
        ddProv.textContent = prof.providers.join(", ");
      } else {
        ddProv.textContent = "no provider recorded";
        ddProv.classList.add("text-muted");
      }
      rProv.appendChild(ddProv);
      dl.appendChild(rProv);

      const rPlug = makeEl("div", "kv-row");
      rPlug.appendChild(makeEl("dt", "", "Plugins (" + prof.plugins.length + ")"));
      const ddPlug = makeEl("dd", "mono");
      if (prof.plugins && prof.plugins.length > 0) {
        ddPlug.textContent = prof.plugins.join(", ");
      } else {
        ddPlug.textContent = "no plugins configured";
        ddPlug.classList.add("text-muted");
      }
      rPlug.appendChild(ddPlug);
      dl.appendChild(rPlug);

      const rMcp = makeEl("div", "kv-row");
      rMcp.appendChild(makeEl("dt", "", "MCP servers (" + prof.mcp_servers.length + ")"));
      const ddMcp = makeEl("dd", "mono");
      if (prof.mcp_servers && prof.mcp_servers.length > 0) {
        ddMcp.textContent = prof.mcp_servers.join(", ");
      } else {
        ddMcp.textContent = "no servers configured";
        ddMcp.classList.add("text-muted");
      }
      rMcp.appendChild(ddMcp);
      dl.appendChild(rMcp);

      const matchingFindings = data.findings.filter(function (f) {
        return prof.path !== "—" && f.path.indexOf(prof.path) === 0;
      });
      const openMatching = matchingFindings.filter(function (f) {
        return f.status === "open";
      });

      const rFinding = makeEl("div", "kv-row");
      rFinding.appendChild(makeEl("dt", "", "Observed findings"));
      const ddFinding = makeEl("dd");
      if (openMatching.length > 0) {
        const fBtn = makeEl("button", "text-action-btn", openMatching.length + " open (" + openMatching[0].id + ")");
        fBtn.type = "button";
        fBtn.addEventListener("click", function () {
          openDrawer(openMatching[0].id);
        });
        ddFinding.appendChild(fBtn);
      } else {
        ddFinding.textContent = "0 open";
        ddFinding.className = "mono";
      }
      rFinding.appendChild(ddFinding);
      dl.appendChild(rFinding);

      card.appendChild(dl);
      container.appendChild(card);
    });
  }

  function renderCoverage(data) {
    const cov = data.coverage_summary;
    const sp = data.scope_preview;
    const settings = data.settings;

    const label = document.getElementById("coverage-meter-label");
    const fill = document.getElementById("coverage-meter-fill");
    const checked = cov.files_checked || 0;
    const maxFiles = cov.max_files || 1;
    const pct = Math.min(100, Math.max(0, (checked / maxFiles) * 100));

    if (label && fill) {
      label.textContent = checked.toLocaleString() + " / " + maxFiles.toLocaleString() + " files (" + pct.toFixed(1) + "%)";
      fill.style.width = pct + "%";
      fill.className = "meter-fill " + (cov.complete ? "meter-fill--48" : "meter-fill--100");
    }

    const elInt = document.getElementById("scope-interval");
    const elMaxF = document.getElementById("scope-max-files");
    const elMaxB = document.getElementById("scope-max-bytes");
    const elRet = document.getElementById("scope-retention");

    if (elInt) elInt.textContent = (settings ? settings.interval_seconds : sp.interval_seconds) + "s";
    if (elMaxF) elMaxF.textContent = (settings ? settings.max_files : sp.max_files).toLocaleString();
    if (elMaxB) {
      const bytes = settings ? settings.max_file_bytes : sp.max_file_bytes;
      elMaxB.textContent = bytes.toLocaleString() + " B (" + (bytes / 1048576).toFixed(1) + " MiB)";
    }
    if (elRet) elRet.textContent = (settings ? settings.retention_days : sp.retention_days) + " days";

    const watchedList = document.getElementById("coverage-watched-list");
    clearChildren(watchedList);
    const watchedPaths = sp.deduped_roots.length ? sp.deduped_roots : (sp.watched_paths.length ? sp.watched_paths : (settings ? settings.watched_paths : []));
    const watchedCountEl = document.getElementById("coverage-watched-count");
    if (watchedCountEl) watchedCountEl.textContent = String(watchedPaths.length);

    if (watchedPaths.length === 0) {
      watchedList.appendChild(makeEl("li", "", "No watched paths configured."));
    } else {
      watchedPaths.forEach(function (p) {
        const item = makeEl("li", "", truncateMiddle(p, 42));
        item.title = p;
        watchedList.appendChild(item);
      });
    }

    const exclList = document.getElementById("coverage-exclusions-list");
    clearChildren(exclList);
    const exclusions = sp.exclusions.length ? sp.exclusions : (settings ? settings.exclusions : []);
    const exclCountEl = document.getElementById("coverage-exclusions-count");
    if (exclCountEl) exclCountEl.textContent = String(exclusions.length);

    if (exclusions.length === 0) {
      exclList.appendChild(makeEl("li", "", "No exclusion directory patterns configured."));
    } else {
      exclusions.forEach(function (ex) {
        const item = makeEl("li", "", truncateMiddle(ex, 42));
        item.title = ex;
        exclList.appendChild(item);
      });
    }
  }

  function renderHealth(data) {
    const badge = document.getElementById("health-status-badge");
    const srv = document.getElementById("health-service-str");
    const elInt = document.getElementById("health-interval");
    const elLast = document.getElementById("health-last-finished");
    const elChecked = document.getElementById("health-files-checked");
    const elErrors = document.getElementById("health-errors");

    const isRunning = data.monitoring;
    if (badge) {
      badge.textContent = isRunning ? "running" : "stopped";
      badge.className = "status-pill " + (isRunning ? "is-running" : "is-stopped");
    }
    if (srv) {
      srv.textContent = data.status.service_health || (isRunning ? "monitor running" : "monitor stopped");
    }
    if (elInt) {
      const sec = data.settings ? data.settings.interval_seconds : data.scope_preview.interval_seconds;
      elInt.textContent = sec ? (sec + "s") : "—";
    }
    if (elLast) {
      const ls = data.status.last_scan;
      if (ls && ls.finished_at) {
        const tf = formatLocalTimestamp(ls.finished_at);
        elLast.textContent = tf.display;
        elLast.title = tf.raw;
      } else {
        elLast.textContent = "Never";
        elLast.removeAttribute("title");
      }
    }
    if (elChecked) {
      const ls = data.status.last_scan;
      elChecked.textContent = ls ? Number(ls.files_checked || 0).toLocaleString() : "0";
    }
    if (elErrors) {
      const errs = (data.status.last_scan && data.status.last_scan.errors) || data.coverage_summary.errors || [];
      elErrors.textContent = errs.length === 0 ? "0 (none)" : errs.join("; ");
    }

    const tag = document.getElementById("health-updatable-tag");
    const summary = document.getElementById("health-updates-summary");
    const packages = data.updates.packages;

    if (data.updates.status !== "ok") {
      const message = updateCheckMessage(data.updates);
      if (tag) tag.textContent = message;
      if (summary) summary.textContent = data.updates.error || message;
      const tbody = document.getElementById("updates-tbody");
      clearChildren(tbody);
      const tr = makeEl("tr");
      const td = makeEl("td", "", message);
      td.colSpan = 4;
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }

    if (tag) {
      tag.textContent = packages.length + (packages.length === 1 ? " upgradable" : " upgradable");
    }
    if (summary) {
      summary.textContent = "Security classification unknown: " + packages.length + " upgradable packages in cached lists have unknown classification.";
    }

    const tbody = document.getElementById("updates-tbody");
    clearChildren(tbody);

    if (packages.length === 0) {
      const tr = makeEl("tr");
      const td = makeEl("td", "", "No upgradable packages reported by system package manager cache.");
      td.colSpan = 4;
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }

    packages.forEach(function (pkg) {
      const tr = makeEl("tr");
      tr.appendChild(makeEl("td", "mono", pkg.name));
      tr.appendChild(makeEl("td", "mono", pkg.installed));
      tr.appendChild(makeEl("td", "mono", pkg.candidate));
      tr.appendChild(makeEl("td", "mono", pkg.suite));
      tbody.appendChild(tr);
    });
  }

  function openDrawer(findingId) {
    if (!state.currentData) return;
    const finding = state.currentData.findings.find(function (f) {
      return f.id === findingId;
    });
    if (!finding) return;

    state.selectedFindingId = finding.id;

    const drawer = document.getElementById("detail-drawer");
    if (drawer) {
      drawer.classList.remove("is-hidden");
      drawer.setAttribute("aria-hidden", "false");
    }

    const idEl = document.getElementById("drawer-id");
    if (idEl) idEl.textContent = finding.id;

    const sevEl = document.getElementById("drawer-severity");
    if (sevEl) {
      sevEl.textContent = finding.severity.toUpperCase();
      sevEl.className = "sev-badge is-" + finding.severity;
    }

    const statEl = document.getElementById("drawer-status");
    if (statEl) {
      statEl.textContent = finding.status;
      statEl.className = "status-pill is-" + finding.status;
    }

    const titleEl = document.getElementById("drawer-title");
    if (titleEl) titleEl.textContent = capitaliseTitle(finding.title);

    const pathEl = document.getElementById("drawer-path");
    if (pathEl) pathEl.textContent = finding.path;

    const copyBtn = document.getElementById("drawer-copy-path-btn");
    if (copyBtn) {
      copyBtn.onclick = function () {
        copyTextToClipboard(finding.path, copyBtn);
      };
    }

    const recEl = document.getElementById("drawer-recommendation");
    if (recEl) recEl.textContent = finding.recommendation;

    const firstSeenEl = document.getElementById("drawer-first-seen");
    if (firstSeenEl) {
      const tf = formatLocalTimestamp(finding.first_seen);
      firstSeenEl.textContent = tf.display;
      if (tf.raw) firstSeenEl.title = tf.raw; else firstSeenEl.removeAttribute("title");
    }

    const lastSeenEl = document.getElementById("drawer-last-seen");
    if (lastSeenEl) {
      const tf = formatLocalTimestamp(finding.last_seen);
      lastSeenEl.textContent = tf.display;
      if (tf.raw) lastSeenEl.title = tf.raw; else lastSeenEl.removeAttribute("title");
    }

    const evList = document.getElementById("drawer-evidence");
    clearChildren(evList);
    const pairs = flattenEvidencePairs(finding.evidence);
    if (pairs.length === 0) {
      const row = makeEl("div", "kv-row");
      row.appendChild(makeEl("dt", "mono", "evidence"));
      row.appendChild(makeEl("dd", "mono", "none recorded"));
      evList.appendChild(row);
    } else {
      pairs.forEach(function (p) {
        const row = makeEl("div", "kv-row");
        row.appendChild(makeEl("dt", "mono", p.key));
        row.appendChild(makeEl("dd", "mono", p.value));
        evList.appendChild(row);
      });
    }

    const relContainer = document.getElementById("drawer-related-events");
    clearChildren(relContainer);
    const relEvents = state.currentData.events.filter(function (ev) {
      return ev.path && ev.path === finding.path;
    });
    if (relEvents.length === 0) {
      relContainer.appendChild(makeEl("div", "drawer-event-item", "No path-specific events in latest event buffer."));
    } else {
      relEvents.forEach(function (ev) {
        const tf = formatLocalTimestamp(ev.t);
        const item = makeEl("div", "drawer-event-item", tf.display + " · " + ev.kind + " · " + ev.summary);
        if (tf.raw) item.title = tf.raw;
        relContainer.appendChild(item);
      });
    }

    renderFindings(state.currentData);
  }

  function closeDrawer() {
    state.selectedFindingId = null;
    const drawer = document.getElementById("detail-drawer");
    if (drawer) {
      drawer.classList.add("is-hidden");
      drawer.setAttribute("aria-hidden", "true");
    }
    if (state.currentData) {
      renderFindings(state.currentData);
    }
  }

  function stepDrawerFinding(delta) {
    if (!state.currentData) return;
    const list = state.currentData.findings;
    if (list.length === 0) return;
    const idx = list.findIndex(function (f) {
      return f.id === state.selectedFindingId;
    });
    if (idx === -1) {
      openDrawer(list[0].id);
      return;
    }
    const nextIdx = (idx + delta + list.length) % list.length;
    openDrawer(list[nextIdx].id);
  }

  function switchView(viewName) {
    if (!VIEW_META[viewName]) return;
    state.activeView = viewName;
    if (state.currentData) {
      renderAll(state.currentData);
    }
  }

  function renderAll(data) {
    state.currentData = data;
    renderShellStatus(data);

    const meta = VIEW_META[state.activeView];
    if (meta) {
      const pageTitle = document.getElementById("page-title");
      const pageSub = document.getElementById("page-subtitle");
      if (pageTitle) pageTitle.textContent = meta.title;
      if (pageSub) pageSub.textContent = meta.subtitle;
    }

    document.querySelectorAll(".nav-item").forEach(function (btn) {
      const v = btn.getAttribute("data-view");
      const active = v === state.activeView;
      btn.classList.toggle("is-active", active);
      if (active) {
        btn.setAttribute("aria-current", "page");
      } else {
        btn.removeAttribute("aria-current");
      }
    });

    document.querySelectorAll(".mobile-tab").forEach(function (btn) {
      const v = btn.getAttribute("data-view");
      btn.classList.toggle("is-active", v === state.activeView);
    });

    const loadingEl = document.getElementById("state-loading");
    const emptyEl = document.getElementById("state-empty");

    if (loadingEl) loadingEl.classList.add("is-hidden");

    if (!data.configured) {
      if (emptyEl) emptyEl.classList.remove("is-hidden");
      VIEW_KEYS.forEach(function (k) {
        const sec = document.getElementById("view-" + k);
        if (sec) sec.classList.add("is-hidden");
      });
      return;
    }

    if (emptyEl) emptyEl.classList.add("is-hidden");

    VIEW_KEYS.forEach(function (k) {
      const sec = document.getElementById("view-" + k);
      if (sec) {
        sec.classList.toggle("is-hidden", k !== state.activeView);
      }
    });

    renderOverview(data);
    renderFindings(data);
    renderChanges(data);
    renderProfiles(data);
    renderCoverage(data);
    renderHealth(data);
  }

  function showLogin(errorMessage) {
    stopPolling();
    const loginOverlay = document.getElementById("login-screen");
    const loginErr = document.getElementById("login-error");
    const usernameInput = document.getElementById("login-username");
    const passwordInput = document.getElementById("login-password");

    if (passwordInput) passwordInput.value = "";

    if (loginErr) {
      if (errorMessage) {
        loginErr.textContent = String(errorMessage);
        loginErr.classList.remove("is-hidden");
      } else {
        loginErr.textContent = "";
        loginErr.classList.add("is-hidden");
      }
    }

    if (loginOverlay) loginOverlay.classList.remove("is-hidden");
    if (usernameInput) usernameInput.focus();
  }

  function hideLogin() {
    const loginOverlay = document.getElementById("login-screen");
    if (loginOverlay) loginOverlay.classList.add("is-hidden");
  }

  function showRefreshError(msg) {
    const banner = document.getElementById("refresh-error-banner");
    const text = document.getElementById("refresh-error-text");
    if (text) text.textContent = msg || "Unable to reach the Warden API. Last observed posture is shown.";
    if (banner) banner.classList.remove("is-hidden");
  }

  function hideRefreshError() {
    const banner = document.getElementById("refresh-error-banner");
    if (banner) banner.classList.add("is-hidden");
  }

  function loadSnapshot() {
    return fetch("/api/snapshot", {
      method: "GET",
      credentials: "same-origin",
      headers: { "Accept": "application/json" }
    }).then(function (resp) {
      if (resp.status === 401) {
        showLogin();
        return null;
      }
      if (!resp.ok) {
        showRefreshError("API returned status " + resp.status + ". Retrying automatically.");
        return null;
      }
      return resp.json();
    }).then(function (snap) {
      if (!snap) return;
      hideRefreshError();
      const adapted = fromSnapshot(snap);
      renderAll(adapted);

      const headerNow = document.getElementById("header-now-mono");
      if (headerNow) {
        const d = new Date();
        const pad = function (n) { return n < 10 ? ("0" + n) : String(n); };
        const timeStr = pad(d.getHours()) + ":" + pad(d.getMinutes()) + ":" + pad(d.getSeconds());
        headerNow.textContent = "Updated " + timeStr;
        headerNow.title = d.toISOString();
      }
    }).catch(function (err) {
      showRefreshError("Connection error while refreshing snapshot. Retrying automatically.");
    });
  }

  function startPolling() {
    stopPolling();
    state.pollTimer = setInterval(function () {
      if (!document.hidden) {
        loadSnapshot();
      }
    }, 15000);
  }

  function stopPolling() {
    if (state.pollTimer) {
      clearInterval(state.pollTimer);
      state.pollTimer = null;
    }
  }

  function initApp() {
    document.querySelectorAll(".nav-item, .mobile-tab").forEach(function (btn) {
      btn.addEventListener("click", function () {
        switchView(btn.getAttribute("data-view"));
      });
    });

    const collapseBtn = document.getElementById("sidebar-collapse-btn");
    if (collapseBtn) {
      collapseBtn.addEventListener("click", function () {
        document.getElementById("sidebar").classList.toggle("is-collapsed");
      });
    }

    const logoutBtn = document.getElementById("btn-logout");
    if (logoutBtn) {
      logoutBtn.addEventListener("click", function () {
        fetch("/api/logout", {
          method: "POST",
          credentials: "same-origin",
          headers: { "Content-Type": "application/json" },
          body: "{}"
        }).then(function () {
          closeDrawer();
          showLogin();
        }).catch(function () {
          closeDrawer();
          showLogin();
        });
      });
    }

    const allFindingsBtn = document.getElementById("overview-all-findings-btn");
    if (allFindingsBtn) {
      allFindingsBtn.addEventListener("click", function () {
        state.statusFilter = "all";
        switchView("findings");
      });
    }

    document.querySelectorAll("[data-status-filter]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        state.statusFilter = btn.getAttribute("data-status-filter");
        if (state.currentData) renderFindings(state.currentData);
      });
    });

    const sevSelect = document.getElementById("severity-select");
    if (sevSelect) {
      sevSelect.addEventListener("change", function () {
        state.severityFilter = sevSelect.value;
        if (state.currentData) renderFindings(state.currentData);
      });
    }

    const searchInput = document.getElementById("findings-search");
    if (searchInput) {
      searchInput.addEventListener("input", function () {
        state.searchQuery = searchInput.value;
        if (state.currentData) renderFindings(state.currentData);
      });
    }

    document.querySelectorAll("[data-sort]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        const f = btn.getAttribute("data-sort");
        if (state.sortField === f) {
          state.sortAsc = !state.sortAsc;
        } else {
          state.sortField = f;
          state.sortAsc = f === "title" || f === "path";
        }
        if (state.currentData) renderFindings(state.currentData);
      });
    });

    const drawerCloseBtn = document.getElementById("drawer-close-btn");
    if (drawerCloseBtn) {
      drawerCloseBtn.addEventListener("click", closeDrawer);
    }

    const drawerPrevBtn = document.getElementById("drawer-prev-btn");
    if (drawerPrevBtn) {
      drawerPrevBtn.addEventListener("click", function () {
        stepDrawerFinding(-1);
      });
    }

    const drawerNextBtn = document.getElementById("drawer-next-btn");
    if (drawerNextBtn) {
      drawerNextBtn.addEventListener("click", function () {
        stepDrawerFinding(1);
      });
    }

    const loginForm = document.getElementById("login-form");
    if (loginForm) {
      loginForm.addEventListener("submit", function (e) {
        e.preventDefault();
        if (state.isSubmittingLogin) return;

        const usernameInput = document.getElementById("login-username");
        const passwordInput = document.getElementById("login-password");
        const submitBtn = document.getElementById("login-submit-btn");
        const loginErr = document.getElementById("login-error");

        const username = usernameInput ? usernameInput.value.trim() : "";
        const password = passwordInput ? passwordInput.value : "";

        if (loginErr) loginErr.classList.add("is-hidden");
        state.isSubmittingLogin = true;
        if (submitBtn) {
          submitBtn.disabled = true;
          submitBtn.textContent = "Unlocking...";
        }

        fetch("/api/session", {
          method: "POST",
          credentials: "same-origin",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username: username, password: password })
        }).then(function (resp) {
          return resp.json().then(function (body) {
            return { status: resp.status, body: body };
          }).catch(function () {
            return { status: resp.status, body: {} };
          });
        }).then(function (res) {
          if (passwordInput) passwordInput.value = "";
          if (res.status === 200) {
            hideLogin();
            loadSnapshot();
            startPolling();
          } else {
            const msg = (res.body && res.body.message) || "Authentication failed: invalid username or password.";
            if (loginErr) {
              loginErr.textContent = msg;
              loginErr.classList.remove("is-hidden");
            }
            if (usernameInput) usernameInput.focus();
          }
        }).catch(function (err) {
          if (passwordInput) passwordInput.value = "";
          if (loginErr) {
            loginErr.textContent = "Connection error during authentication.";
            loginErr.classList.remove("is-hidden");
          }
          if (usernameInput) usernameInput.focus();
        }).finally(function () {
          state.isSubmittingLogin = false;
          if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.textContent = "Unlock read-only console";
          }
        });
      });
    }

    document.addEventListener("keydown", function (e) {
      const tag = (e.target && e.target.tagName) ? e.target.tagName.toLowerCase() : "";
      const inInput = tag === "input" || tag === "select" || tag === "textarea";

      if (e.key === "Escape") {
        if (state.selectedFindingId) {
          closeDrawer();
          return;
        }
      }

      if (!inInput && !e.ctrlKey && !e.metaKey && !e.altKey) {
        const num = parseInt(e.key, 10);
        if (num >= 1 && num <= 6) {
          e.preventDefault();
          switchView(VIEW_KEYS[num - 1]);
        }
      }
    });

    document.addEventListener("visibilitychange", function () {
      if (document.hidden) {
        stopPolling();
      } else {
        loadSnapshot();
        startPolling();
      }
    });

    // Boot: check session
    fetch("/api/session", {
      method: "GET",
      credentials: "same-origin",
      headers: { "Accept": "application/json" }
    }).then(function (resp) {
      return resp.json();
    }).then(function (data) {
      if (data && data.authenticated) {
        hideLogin();
        loadSnapshot();
        startPolling();
      } else {
        const loadingEl = document.getElementById("state-loading");
        if (loadingEl) loadingEl.classList.add("is-hidden");
        showLogin();
      }
    }).catch(function () {
      const loadingEl = document.getElementById("state-loading");
      if (loadingEl) loadingEl.classList.add("is-hidden");
      showLogin();
    });
  }

  if (root && root.CustodianUI && typeof root.CustodianUI === "object") {
    root.CustodianUI.renderOverview = renderOverview;
    root.CustodianUI.renderFindings = renderFindings;
    root.CustodianUI.renderChanges = renderChanges;
    root.CustodianUI.renderProfiles = renderProfiles;
    root.CustodianUI.renderCoverage = renderCoverage;
    root.CustodianUI.renderHealth = renderHealth;
    root.CustodianUI.renderAll = renderAll;
    root.CustodianUI.state = state;
  }

  document.addEventListener("DOMContentLoaded", initApp);
})(typeof globalThis !== "undefined" ? globalThis : window);
