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
      subtitle: "Security threats, antivirus detections, and optional permission alerts across watched roots"
    },
    changes: {
      title: "Changes",
      subtitle: "Observed filesystem and scan events grouped by scan window"
    },
    apps: {
      title: "Plugins & Apps",
      subtitle: "Installed Hermes plugins, MCP servers, OS apps/packages, and updates"
    },
    profiles: {
      title: "Profiles & Models",
      subtitle: "Configured Hermes agent profiles, models, plugins, and MCP servers"
    },
    coverage: {
      title: "Coverage & Scope",
      subtitle: "Protection toggles, watched directories, exclusions, and scan budget"
    },
    health: {
      title: "System Health",
      subtitle: "Warden monitor service heartbeat and cached OS updates"
    }
  };

  const VIEW_KEYS = ["overview", "findings", "changes", "apps", "profiles", "coverage", "health"];
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
      const evidence = (f.evidence && typeof f.evidence === "object") ? f.evidence : {};
      const modeOnly = String(f.title || "").indexOf("group/other permission bits") !== -1;
      const assessmentState = modeOnly ? (evidence.assessment_version === 2 ? "mode_only" : "previous_rule") : "recorded";
      return {
        assessment_state: assessmentState,
        id: String(f.id || ("find-" + (idx + 1))),
        severity: String(f.severity || "low").toLowerCase(),
        category: String(f.category || evidence.category || (modeOnly ? "permissions" : "security")),
        status: String(f.status || "open").toLowerCase(),
        title: String(f.title || "Untitled finding"),
        path: String(f.path || ""),
        evidence: (f.evidence && typeof f.evidence === "object") ? f.evidence : {},
        recommendation: String(f.recommendation || "Inspect this file and review the evidence carefully."),
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
      retention_days: Number(settings.retention_days || 0),
      check_permissions: Boolean(settings.check_permissions),
      security_scan: settings.security_scan !== false,
      use_system_av: settings.use_system_av !== false
    } : null;

    const rawCovState = String(cov.state || (configured ? "complete" : "unconfigured")).toLowerCase();
    const covState = (rawCovState === "complete" || rawCovState === "heal" + "thy") ? "complete" : rawCovState;
    const isCovComplete = covState === "complete" && Boolean(cov.complete !== false && (!lastScan || lastScan.complete !== false));
    const covReason = String(cov.reason || (configured ? "" : "Hermes Security Warden is not configured yet. Run 'warden setup' via terminal to select monitored roots."));
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
        verdictDetail = "Security threats or suspicious files were detected in your watched scope. Inspect each finding for details and remediation.";
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
        read_only_notice: String(sp.read_only_notice || "Dashboard is read-only. Modify scope or budgets via CLI/TUI (warden setup).")
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
      av_status: (snap.av_status && typeof snap.av_status === "object") ? snap.av_status : {
        available: false,
        label: "Built-in scanner only",
        builtin_heuristics: true,
        security_scan_enabled: adaptedSettings ? adaptedSettings.security_scan : true,
        use_system_av: adaptedSettings ? adaptedSettings.use_system_av : true,
        check_permissions: adaptedSettings ? adaptedSettings.check_permissions : false
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
    categoryFilter: "all",
    searchQuery: "",
    sortField: "severity",
    sortAsc: false,
    kindFilter: "all",
    expandedEvents: {},
    selectedFindingId: null,
    currentData: null,
    appsData: null,
    appsError: "",
    appsLoading: false,
    appsFilter: "all",
    appsSearch: "",
    appsLimit: 200,
    quarantineItems: [],
    allowlistEntries: [],
    iocHashes: [],
    inflightUpdates: {},
    toastTimer: null,
    isScanning: false,
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
            stoppedText.textContent = "The local warden monitor process is not running. Last scan was finished at " + tf.display + "; file changes since then are not observed.";
            stoppedText.title = tf.raw;
          } else {
            stoppedText.textContent = "The local warden monitor process is not running. File changes are not currently observed.";
            stoppedText.removeAttribute("title");
          }
        }
      } else {
        stoppedBanner.classList.add("is-hidden");
      }
    }
  }

  function findingSeverityLabel(finding) {
    return finding.assessment_state === "previous_rule" ? "REASSESS" : finding.severity.toUpperCase();
  }

  function findingSeverityClass(finding) {
    return finding.assessment_state === "previous_rule" ? "is-review" : "is-" + finding.severity;
  }

  function renderOverview(data) {
    const verdict = data.verdict;
    const priorityFindings = data.open_findings.filter(function (f) { return f.assessment_state !== "previous_rule"; });
    const historicalCount = data.open_findings.length - priorityFindings.length;
    const historyPanel = document.getElementById("overview-history-panel");
    if (historyPanel) historyPanel.classList.toggle("is-hidden", historicalCount === 0);
    const historyCount = document.getElementById("overview-history-count");
    if (historyCount) historyCount.textContent = String(historicalCount);
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
      sentence.textContent = historicalCount && priorityFindings.length === 0
        ? "No current priority assessments. Historical findings require a fresh scan."
        : verdict.sentence;
    }
    if (detail) {
      const reassessCount = data.open_findings.filter(function (f) { return f.assessment_state === "previous_rule"; }).length;
      detail.textContent = verdict.detail + (reassessCount ? " " + reassessCount + (reassessCount === 1 ? " finding needs" : " findings need") + " reassessment under the revised permission rule. Previous severity is retained in history, not confirmed as current." : "");
      const ls = data.status && data.status.last_scan;
      if (ls && ls.finished_at && verdict.code === "QUIET") {
        detail.title = formatLocalTimestamp(ls.finished_at).raw;
      } else {
        detail.removeAttribute("title");
      }
    }

    const openCountEl = document.getElementById("overview-open-count");
    if (openCountEl) {
      openCountEl.textContent = String(priorityFindings.length);
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
    } else if (priorityFindings.length === 0) {
      const emptyRow = makeEl("div", "compact-empty-row");
      const msg = makeEl(
        "span",
        "",
        historicalCount > 0
          ? "Previous-rule observations are listed separately below. Current coverage remains unverified."
          : data.findings.length > 0
          ? ("0 open findings in current snapshot. " + data.findings.length + " resolved findings remain in history.")
          : "0 open findings across watched paths."
      );
      emptyRow.appendChild(msg);
      if (data.findings.length > 0 && historicalCount === 0) {
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
      priorityFindings.slice().sort(function (a, b) {
        return (SEVERITY_RANK[b.severity] || 0) - (SEVERITY_RANK[a.severity] || 0);
      }).slice(0, 5).forEach(function (f) {
        const row = makeEl("button", "compact-finding-row");
        row.type = "button";
        row.setAttribute("role", "listitem");
        if (state.selectedFindingId === f.id) {
          row.classList.add("is-selected");
        }

        const sev = makeEl("span", "sev-badge " + findingSeverityClass(f), findingSeverityLabel(f));
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

    const avVal = document.getElementById("fact-av-val");
    const avSub = document.getElementById("fact-av-sub");
    if (avVal && avSub) {
      const av = data.av_status || {};
      const enabled = av.security_scan_enabled !== false;
      const sysAvActive = Boolean(av.available && av.use_system_av !== false);
      avVal.textContent = enabled ? (sysAvActive ? ("Active + " + (av.label || "System AV")) : "Active (Built-in)") : "Paused";
      const permLabel = av.check_permissions ? "Perm checks: ON" : "Perm checks: OFF";
      avSub.textContent = (sysAvActive ? "Signature + Heuristic AV" : "Heuristics + IOC + Agent") + " · " + permLabel;
    }

    const updVal = document.getElementById("fact-updates-val");
    const updSub = document.getElementById("fact-updates-sub");
    if (updVal && updSub) {
      const pkgCount = data.updates.packages.length;
      const available = data.updates.status === "ok";
      updVal.textContent = available ? pkgCount + " upgradable" : updateCheckMessage(data.updates);
      updSub.textContent = available ? "security classification unknown" : data.updates.error;
    }

    const navAppsCount = document.getElementById("nav-apps-updates-count");
    if (navAppsCount) {
      const uCount = data.updates.status === "ok" ? data.updates.packages.length : 0;
      navAppsCount.textContent = String(uCount);
      navAppsCount.className = "nav-count" + (uCount === 0 ? " is-zero" : "");
    }
  }

  function updateCheckMessage(updates) {
    return updates.status === "unknown" ? "Unknown" : "Update check unavailable";
  }

  function renderFindings(data) {
    const findings = data.findings;
    const openCount = data.open_findings.length;
    const resolvedCount = findings.filter(function (f) { return f.status === "resolved"; }).length;

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
      if (state.severityFilter === "review") {
        if (f.assessment_state !== "previous_rule") return false;
      } else if (state.severityFilter !== "all" && (f.assessment_state === "previous_rule" || f.severity !== state.severityFilter)) return false;
      if (state.categoryFilter !== "all" && f.category !== state.categoryFilter) return false;
      if (query) {
        const hay = (
          f.id + " " +
          f.title + " " +
          f.category + " " +
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
      tdSev.appendChild(makeEl("span", "sev-badge " + findingSeverityClass(f), findingSeverityLabel(f)));

      const tdTitle = makeEl("td", "finding-row-title");
      tdTitle.appendChild(document.createTextNode(capitaliseTitle(f.title)));
      if (f.category) {
        const catTag = makeEl("span", "mono-tag apps-inline-badge", f.category);
        tdTitle.appendChild(catTag);
      }
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
        inv.explanation || "Profile discovery was not approved in terminal setup. Run 'warden setup' in a terminal to consent to hermes_root inspection."
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
        const item = makeEl("li", "mono-list-row");
        const labelSpan = makeEl("span", "mono-list-text", truncateMiddle(p, 42));
        labelSpan.title = p;
        item.appendChild(labelSpan);
        if (watchedPaths.length > 1) {
          const rmBtn = makeEl("button", "quiet-btn list-remove-btn", "Remove");
          rmBtn.type = "button";
          rmBtn.addEventListener("click", function () {
            mutateScope("remove_path", p);
          });
          item.appendChild(rmBtn);
        }
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
        const item = makeEl("li", "mono-list-row");
        const labelSpan = makeEl("span", "mono-list-text", truncateMiddle(ex, 42));
        labelSpan.title = ex;
        item.appendChild(labelSpan);
        const rmBtn = makeEl("button", "quiet-btn list-remove-btn", "Remove");
        rmBtn.type = "button";
        rmBtn.addEventListener("click", function () {
          mutateScope("remove_exclusion", ex);
        });
        item.appendChild(rmBtn);
        exclList.appendChild(item);
      });
    }

    const tSec = document.getElementById("toggle-security-scan");
    const tAv = document.getElementById("toggle-system-av");
    const tPerm = document.getElementById("toggle-check-permissions");
    const tStatus = document.getElementById("protection-settings-status");
    if (settings) {
      if (tSec) tSec.checked = settings.security_scan !== false;
      if (tAv) tAv.checked = settings.use_system_av !== false;
      if (tPerm) tPerm.checked = Boolean(settings.check_permissions);
      if (tStatus) {
        tStatus.textContent = settings.security_scan !== false ? "AV Active" : "AV Paused";
      }
    }
  }

  function showAppsActionBanner(title, message, cliCommand, tone) {
    const banner = document.getElementById("apps-action-banner");
    const titleEl = document.getElementById("apps-action-title");
    const msgEl = document.getElementById("apps-action-message");
    const cmdWrap = document.getElementById("apps-action-cmd-wrap");
    const cmdEl = document.getElementById("apps-action-cmd");
    const copyBtn = document.getElementById("apps-action-copy-btn");
    if (!banner) return;
    const cls = tone === true || tone === "error" ? "is-error" : (tone === "warn" ? "is-warn" : "is-success");
    banner.classList.remove("is-hidden", "is-error", "is-success", "is-warn");
    banner.classList.add(cls);
    if (titleEl) titleEl.textContent = title || "Update status";
    if (msgEl) msgEl.textContent = message || "";
    if (cmdWrap && cmdEl) {
      if (cliCommand) {
        cmdEl.textContent = cliCommand;
        cmdWrap.classList.remove("is-hidden");
        if (copyBtn) {
          copyBtn.onclick = function () { copyTextToClipboard(cliCommand, copyBtn); };
        }
      } else {
        cmdWrap.classList.add("is-hidden");
      }
    }
    if (typeof banner.scrollIntoView === "function") {
      banner.scrollIntoView({ behavior: "smooth", block: "nearest" });
    }
  }

  function triggerUpdate(targetType, targetName, btnEl, installation) {
    const key = targetType + "::" + (targetName || "*");
    if (state.inflightUpdates[key]) return Promise.resolve();
    state.inflightUpdates[key] = true;
    const origText = btnEl ? btnEl.textContent : "";
    if (btnEl) {
      btnEl.disabled = true;
      btnEl.textContent = "Updating...";
    }
    const payload = { target_type: targetType, target_name: targetName || null };
    if (installation) payload.installation = installation;
    return fetch("/api/actions/update", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify(payload)
    }).then(function (resp) {
      return resp.json().catch(function () { return {}; }).then(function (body) {
        return { status: resp.status, body: body };
      });
    }).then(function (res) {
      const b = res.body || {};
      if (res.status === 401) {
        showLogin();
        return;
      }
      if (res.status === 409) {
        showAppsActionBanner("Action in progress", b.message || "Another scan or update is already running.", "", "warn");
        return;
      }
      if (b.status === "needs_elevation") {
        showAppsActionBanner("Administrator approval needed", b.message, b.cli_command || "", "warn");
      } else if (res.status >= 200 && res.status < 300 && b.ok) {
        showAppsActionBanner("Update complete", b.message || "Updated successfully.", b.cli_command || "", "success");
        loadApps(true);
        loadSnapshot();
      } else {
        showAppsActionBanner("Update failed", b.message || ("API returned status " + res.status + "."), b.cli_command || "", "error");
      }
    }).catch(function () {
      showAppsActionBanner("Connection error", "Could not reach the Warden API to run the update.", "", "error");
    }).finally(function () {
      delete state.inflightUpdates[key];
      if (btnEl) {
        btnEl.disabled = false;
        btnEl.textContent = origText;
      }
      if (state.activeView === "apps") renderApps();
    });
  }

  function loadApps(force) {
    if (state.appsLoading && !force) return Promise.resolve();
    state.appsLoading = true;
    state.appsError = "";
    const checkBtn = document.getElementById("btn-check-updates");
    if (checkBtn) {
      checkBtn.disabled = true;
      checkBtn.textContent = "Checking...";
    }
    return fetch("/api/apps", {
      method: "GET",
      credentials: "same-origin",
      headers: { "Accept": "application/json" }
    }).then(function (resp) {
      if (resp.status === 401) {
        showLogin();
        return null;
      }
      return resp.json().catch(function () { return null; }).then(function (body) {
        if (!resp.ok || !body) {
          state.appsError = (body && body.error) ? String(body.error) : ("Could not load installed plugins and apps (HTTP " + resp.status + ").");
          renderApps();
          return null;
        }
        return body;
      });
    }).then(function (payload) {
      if (payload) {
        state.appsData = payload;
        state.appsError = payload.error ? String(payload.error) : "";
        const navAppsCount = document.getElementById("nav-apps-updates-count");
        if (navAppsCount && payload.summary) {
          const uCount = Number(payload.summary.updatable_count || 0);
          navAppsCount.textContent = String(uCount);
          navAppsCount.className = "nav-count" + (uCount === 0 ? " is-zero" : "");
        }
        renderApps();
      }
    }).catch(function () {
      state.appsError = "Network error while loading installed plugins and apps.";
      renderApps();
    }).finally(function () {
      state.appsLoading = false;
      if (checkBtn) {
        checkBtn.disabled = false;
        checkBtn.textContent = "Check for updates";
      }
    });
  }

  function renderApps() {
    const apps = state.appsData;
    const plugTbody = document.getElementById("apps-plugins-tbody");
    const plugCount = document.getElementById("apps-plugins-count");
    const mcpList = document.getElementById("apps-mcp-list");
    const mcpCount = document.getElementById("apps-mcp-count");
    const osTbody = document.getElementById("apps-os-tbody");
    const osCount = document.getElementById("apps-os-count");
    const truncEl = document.getElementById("apps-os-truncation");
    if (!plugTbody || !osTbody) return;

    if (state.appsError && !apps) {
      clearChildren(plugTbody);
      const tr = makeEl("tr");
      const td = makeEl("td", "table-cell-error", state.appsError);
      td.colSpan = 5;
      tr.appendChild(td);
      plugTbody.appendChild(tr);
      clearChildren(osTbody);
      const tr2 = makeEl("tr");
      const td2 = makeEl("td", "table-cell-error", state.appsError);
      td2.colSpan = 5;
      tr2.appendChild(td2);
      osTbody.appendChild(tr2);
      return;
    }

    if (!apps) {
      clearChildren(plugTbody);
      const tr = makeEl("tr");
      const td = makeEl("td", "text-muted", "Loading installed plugins and apps...");
      td.colSpan = 5;
      tr.appendChild(td);
      plugTbody.appendChild(tr);
      clearChildren(osTbody);
      const tr2 = makeEl("tr");
      const td2 = makeEl("td", "text-muted", "Loading installed OS apps and packages...");
      td2.colSpan = 5;
      tr2.appendChild(td2);
      osTbody.appendChild(tr2);
      return;
    }

    const plugins = Array.isArray(apps.hermes_plugins) ? apps.hermes_plugins : [];
    const mcps = Array.isArray(apps.mcp_servers) ? apps.mcp_servers : [];
    const osApps = Array.isArray(apps.os_apps) ? apps.os_apps : [];
    const summary = apps.summary || {};

    if (plugCount) plugCount.textContent = String(plugins.length);
    clearChildren(plugTbody);
    if (plugins.length === 0) {
      const tr = makeEl("tr");
      const emptyMsg = apps.discovery_approved === false
        ? "Hermes plugin discovery requires approval in terminal setup (warden setup)."
        : "No Hermes plugins discovered in consented Hermes root.";
      const td = makeEl("td", "text-muted", emptyMsg);
      td.colSpan = 5;
      tr.appendChild(td);
      plugTbody.appendChild(tr);
    } else {
      plugins.forEach(function (p) {
        const pluginId = p.id || p.name;
        const inflightKey = "hermes_plugin::" + pluginId;
        const tr = makeEl("tr");
        const tdName = makeEl("td");
        tdName.appendChild(makeEl("div", "finding-row-title", p.name));
        if (p.description) tdName.appendChild(makeEl("div", "text-muted apps-sub-desc", p.description));
        tr.appendChild(tdName);
        tr.appendChild(makeEl("td", "mono", p.version || "installed"));
        const tdSrc = makeEl("td", "mono", truncateMiddle(p.source || "local", 36));
        tdSrc.title = p.source || "";
        tr.appendChild(tdSrc);
        const tdStat = makeEl("td");
        const isEnabled = p.enabled !== false;
        tdStat.appendChild(makeEl("span", "status-pill " + (isEnabled ? "is-running" : "is-stopped"), isEnabled ? "installed" : "disabled"));
        tr.appendChild(tdStat);
        const tdAct = makeEl("td");
        if (p.updatable !== false) {
          const updBtn = makeEl("button", "quiet-btn update-row-btn", state.inflightUpdates[inflightKey] ? "Updating..." : "Update");
          updBtn.type = "button";
          updBtn.disabled = Boolean(state.inflightUpdates[inflightKey]);
          updBtn.addEventListener("click", function () {
            triggerUpdate("hermes_plugin", pluginId, updBtn);
          });
          tdAct.appendChild(updBtn);
        } else {
          tdAct.appendChild(makeEl("span", "text-muted", "Local"));
        }
        tr.appendChild(tdAct);
        plugTbody.appendChild(tr);
      });
    }

    if (mcpCount) mcpCount.textContent = String(mcps.length);
    if (mcpList) {
      clearChildren(mcpList);
      if (mcps.length === 0) {
        mcpList.appendChild(makeEl("span", "text-muted", "No MCP servers recorded in consented Hermes profiles."));
      } else {
        mcps.forEach(function (m) {
          const chip = makeEl("span", "mono-tag", m.name + (m.profile ? (" (" + m.profile + ")") : ""));
          mcpList.appendChild(chip);
        });
      }
    }

    document.querySelectorAll("[data-apps-filter]").forEach(function (btn) {
      btn.classList.toggle("is-active", btn.getAttribute("data-apps-filter") === state.appsFilter);
    });

    const query = state.appsSearch.trim().toLowerCase();
    const filteredOs = osApps.filter(function (a) {
      if (state.appsFilter === "upgradable" && !a.update_available) return false;
      if (state.appsFilter === "security" && a.security !== true) return false;
      if (state.appsFilter === "flatpak" && a.manager !== "flatpak") return false;
      if (state.appsFilter === "snap" && a.manager !== "snap") return false;
      if (state.appsFilter === "apt" && a.manager !== "apt" && a.manager !== "brew" && a.manager !== "macos_app" && a.manager !== "softwareupdate" && a.manager !== "windowsupdate") return false;
      if (query) {
        const hay = ((a.name || "") + " " + (a.package_id || "") + " " + (a.manager || "") + " " + (a.section || "") + " " + (a.installed_version || "")).toLowerCase();
        if (hay.indexOf(query) === -1) return false;
      }
      return true;
    });

    if (osCount) osCount.textContent = String(summary.os_apps_count || osApps.length);
    clearChildren(osTbody);
    if (filteredOs.length === 0) {
      const tr = makeEl("tr");
      const td = makeEl("td", "text-muted", "No installed apps or packages match the current filter.");
      td.colSpan = 5;
      tr.appendChild(td);
      osTbody.appendChild(tr);
      if (truncEl) truncEl.classList.add("is-hidden");
    } else {
      const shown = filteredOs.slice(0, state.appsLimit);
      shown.forEach(function (a) {
        const tr = makeEl("tr");
        const tdName = makeEl("td");
        tdName.appendChild(makeEl("span", "mono", a.name));
        if (a.security === true) {
          const secBadge = makeEl("span", "sev-badge is-high apps-inline-badge", "SECURITY");
          tdName.appendChild(secBadge);
        }
        tr.appendChild(tdName);
        tr.appendChild(makeEl("td", "mono", a.manager || "system"));
        tr.appendChild(makeEl("td", "mono", a.installed_version || "—"));
        const tdAvail = makeEl("td", "mono", a.update_available ? (a.candidate_version || "available") : "Up to date");
        if (!a.update_available) tdAvail.classList.add("text-muted");
        tr.appendChild(tdAvail);
        const tdAct = makeEl("td");
        if (a.update_available || a.manager === "flatpak" || a.manager === "brew") {
          const targetType = a.manager === "flatpak" ? "flatpak" : (a.manager === "brew" ? "brew" : "os_package");
          const targetName = a.package_id || a.name;
          const inflightKey = targetType + "::" + targetName;
          const btn = makeEl("button", "quiet-btn update-row-btn", state.inflightUpdates[inflightKey] ? "Updating..." : "Update");
          btn.type = "button";
          btn.disabled = Boolean(state.inflightUpdates[inflightKey]);
          btn.addEventListener("click", function () {
            triggerUpdate(targetType, targetName, btn, a.installation || null);
          });
          tdAct.appendChild(btn);
        } else {
          tdAct.appendChild(makeEl("span", "text-muted", "—"));
        }
        tr.appendChild(tdAct);
        osTbody.appendChild(tr);
      });
      if (truncEl) {
        const truncText = document.getElementById("apps-os-truncation-text");
        const moreBtn = document.getElementById("btn-apps-load-more");
        const total = Math.max(filteredOs.length, Number(summary.os_apps_count || 0));
        if (filteredOs.length > shown.length || (state.appsFilter === "all" && !query && total > shown.length)) {
          const msg = "Showing " + shown.length + " of " + total + " matching items.";
          if (truncText) truncText.textContent = msg; else truncEl.textContent = msg;
          if (moreBtn) moreBtn.classList.toggle("is-hidden", filteredOs.length <= shown.length);
          truncEl.classList.remove("is-hidden");
        } else {
          truncEl.classList.add("is-hidden");
        }
      }
    }
  }

  function showToast(message, tone) {
    const toast = document.getElementById("warden-toast");
    const textEl = document.getElementById("warden-toast-text");
    if (!toast || !textEl) return;
    if (state.toastTimer) {
      clearTimeout(state.toastTimer);
      state.toastTimer = null;
    }
    textEl.textContent = String(message || "");
    toast.classList.remove("is-hidden", "is-error", "is-warn", "is-success");
    toast.classList.add(tone === "error" ? "is-error" : (tone === "warn" ? "is-warn" : "is-success"));
    state.toastTimer = setTimeout(function () {
      toast.classList.add("is-hidden");
    }, 5500);
  }

  function applyTheme(theme) {
    const normalized = theme === "light" ? "light" : "dark";
    if (document.documentElement) {
      document.documentElement.setAttribute("data-theme", normalized);
    }
    const btn = document.getElementById("btn-theme-toggle");
    if (btn) {
      btn.textContent = normalized === "light" ? "Dark" : "Light";
    }
    try {
      if (typeof localStorage !== "undefined") {
        localStorage.setItem("warden_theme", normalized);
      }
    } catch (_e) {}
  }

  function runCustomTargetScan(targetPath) {
    const trimmed = String(targetPath || "").trim();
    if (!trimmed) return;
    const submitBtn = document.getElementById("btn-quick-scan-submit");
    const resBox = document.getElementById("quick-scan-results");
    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtn.textContent = "Scanning...";
    }
    fetch("/api/actions/scan-target", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify({ path: trimmed })
    }).then(function (resp) {
      if (resp.status === 401) { showLogin(); return null; }
      return resp.json().catch(function () { return { ok: false, message: "Scan failed (HTTP " + resp.status + ")" }; });
    }).then(function (res) {
      if (!res || !resBox) return;
      clearChildren(resBox);
      resBox.classList.remove("is-hidden");
      if (!res.ok) {
        resBox.appendChild(makeEl("div", "text-error", res.message || "Target scan failed."));
        showToast(res.message || "Target scan failed.", "error");
        return;
      }
      const findings = Array.isArray(res.findings) ? res.findings : [];
      const summary = makeEl(
        "div",
        "quick-scan-summary mono",
        "Scanned " + res.target + " (" + res.files_checked + " files in " + res.duration_ms + " ms) · " + findings.length + " finding" + (findings.length === 1 ? "" : "s")
      );
      resBox.appendChild(summary);
      if (findings.length === 0) {
        resBox.appendChild(makeEl("div", "text-muted", "No threats detected in target."));
        showToast("Target scan finished: 0 findings.", "success");
      } else {
        findings.slice(0, 20).forEach(function (f) {
          const row = makeEl("div", "quick-scan-hit");
          row.appendChild(makeEl("span", "sev-badge is-" + String(f.severity || "high").toLowerCase(), String(f.severity || "HIGH").toUpperCase()));
          row.appendChild(makeEl("span", "finding-row-title", capitaliseTitle(f.title)));
          row.appendChild(makeEl("span", "mono text-muted", truncateMiddle(f.path, 48)));
          resBox.appendChild(row);
        });
        showToast("Target scan found " + findings.length + " threat(s).", "warn");
      }
    }).catch(function () {
      showToast("Connection error during target scan.", "error");
    }).finally(function () {
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.textContent = "Scan path";
      }
    });
  }

  function mutateScope(action, value) {
    return fetch("/api/actions/scope", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify({ action: action, value: value })
    }).then(function (resp) {
      if (resp.status === 401) { showLogin(); return null; }
      return resp.json().catch(function () { return { ok: false, message: "Scope update failed." }; });
    }).then(function (res) {
      if (!res) return;
      if (res.ok) {
        showToast("Scope updated. Click Scan now to refresh baseline.", "success");
        loadSnapshot();
      } else {
        showToast(res.message || "Could not update scope.", "error");
      }
    }).catch(function () {
      showToast("Connection error updating scope.", "error");
    });
  }

  function loadRemediationData() {
    Promise.all([
      fetch("/api/quarantine", { method: "GET", credentials: "same-origin", headers: { "Accept": "application/json" } })
        .then(function (r) { return r.ok ? r.json() : { items: [] }; })
        .catch(function () { return { items: [] }; }),
      fetch("/api/allowlist", { method: "GET", credentials: "same-origin", headers: { "Accept": "application/json" } })
        .then(function (r) { return r.ok ? r.json() : { entries: [] }; })
        .catch(function () { return { entries: [] }; })
    ]).then(function (results) {
      state.quarantineItems = Array.isArray(results[0].items) ? results[0].items : [];
      state.allowlistEntries = Array.isArray(results[1].entries) ? results[1].entries : [];
      renderRemediationPanels();
    });
  }

  function renderRemediationPanels() {
    const qTbody = document.getElementById("quarantine-tbody");
    const qCount = document.getElementById("quarantine-count");
    if (qCount) qCount.textContent = String(state.quarantineItems.length);
    if (qTbody) {
      clearChildren(qTbody);
      if (state.quarantineItems.length === 0) {
        const tr = makeEl("tr");
        const td = makeEl("td", "text-muted", "No files in quarantine.");
        td.colSpan = 3;
        tr.appendChild(td);
        qTbody.appendChild(tr);
      } else {
        state.quarantineItems.forEach(function (it) {
          const tr = makeEl("tr");
          const tdPath = makeEl("td", "mono", truncateMiddle(it.original_path, 38));
          tdPath.title = it.original_path + (it.sha256 ? (" (SHA-256: " + it.sha256 + ")") : "");
          tr.appendChild(tdPath);
          const tf = formatLocalTimestamp(it.quarantined_at);
          tr.appendChild(makeEl("td", "mono", tf.display));
          const tdAct = makeEl("td", "inline-btn-cell");
          const restoreBtn = makeEl("button", "quiet-btn update-row-btn", "Restore");
          restoreBtn.type = "button";
          restoreBtn.addEventListener("click", function () {
            quarantineAction("restore", { id: it.id });
          });
          const delBtn = makeEl("button", "quiet-btn update-row-btn text-error", "Delete");
          delBtn.type = "button";
          delBtn.addEventListener("click", function () {
            if (typeof window !== "undefined" && typeof window.confirm === "function" && !window.confirm("Permanently delete quarantined file?")) return;
            quarantineAction("delete", { id: it.id });
          });
          tdAct.appendChild(restoreBtn);
          tdAct.appendChild(delBtn);
          tr.appendChild(tdAct);
          qTbody.appendChild(tr);
        });
      }
    }

    const aTbody = document.getElementById("allowlist-tbody");
    const aCount = document.getElementById("allowlist-count");
    if (aCount) aCount.textContent = String(state.allowlistEntries.length);
    if (aTbody) {
      clearChildren(aTbody);
      if (state.allowlistEntries.length === 0) {
        const tr = makeEl("tr");
        const td = makeEl("td", "text-muted", "No allowlisted / ignored findings.");
        td.colSpan = 3;
        tr.appendChild(td);
        aTbody.appendChild(tr);
      } else {
        state.allowlistEntries.forEach(function (e) {
          const tr = makeEl("tr");
          const label = (e.path ? truncateMiddle(e.path, 32) : (e.finding_id || "—")) + (e.rule ? (" [" + e.rule + "]") : "");
          const tdPath = makeEl("td", "mono", label);
          tdPath.title = e.path || e.finding_id || "";
          tr.appendChild(tdPath);
          tr.appendChild(makeEl("td", "text-muted", e.reason || "Ignored"));
          const tdAct = makeEl("td");
          const rmBtn = makeEl("button", "quiet-btn update-row-btn", "Remove");
          rmBtn.type = "button";
          rmBtn.addEventListener("click", function () {
            allowlistAction("remove", { id: e.id });
          });
          tdAct.appendChild(rmBtn);
          tr.appendChild(tdAct);
          aTbody.appendChild(tr);
        });
      }
    }
  }

  function quarantineAction(action, payload) {
    const body = Object.assign({ action: action }, payload || {});
    return fetch("/api/actions/quarantine", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify(body)
    }).then(function (resp) {
      if (resp.status === 401) { showLogin(); return null; }
      return resp.json().catch(function () { return { ok: false, message: "Quarantine request failed." }; });
    }).then(function (res) {
      if (!res) return;
      if (res.ok) {
        const msg = action === "quarantine" ? "File moved to quarantine." : (action === "restore" ? "File restored from quarantine." : "Quarantined file deleted.");
        showToast(msg, "success");
        if (action === "quarantine") {
          closeDrawer();
          triggerScan();
        }
        loadRemediationData();
        loadSnapshot();
      } else {
        showToast(res.message || "Quarantine action failed.", "error");
      }
    }).catch(function () {
      showToast("Connection error during quarantine action.", "error");
    });
  }

  function allowlistAction(action, payload) {
    const body = Object.assign({ action: action }, payload || {});
    return fetch("/api/actions/allowlist", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify(body)
    }).then(function (resp) {
      if (resp.status === 401) { showLogin(); return null; }
      return resp.json().catch(function () { return { ok: false, message: "Allowlist request failed." }; });
    }).then(function (res) {
      if (!res) return;
      if (res.ok) {
        showToast(action === "add" ? "Finding added to allowlist. Rescanning..." : "Allowlist entry removed.", "success");
        if (action === "add") {
          closeDrawer();
          triggerScan();
        }
        loadRemediationData();
      } else {
        showToast(res.message || "Allowlist update failed.", "error");
      }
    }).catch(function () {
      showToast("Connection error updating allowlist.", "error");
    });
  }

  function loadIocData() {
    fetch("/api/ioc", {
      method: "GET",
      credentials: "same-origin",
      headers: { "Accept": "application/json" }
    }).then(function (r) {
      return r.ok ? r.json() : { hashes: [] };
    }).then(function (data) {
      state.iocHashes = Array.isArray(data.hashes) ? data.hashes : [];
      renderIocTable();
    }).catch(function () {});
  }

  function renderIocTable() {
    const tbody = document.getElementById("ioc-tbody");
    const countEl = document.getElementById("ioc-count");
    if (countEl) countEl.textContent = String(state.iocHashes.length);
    if (!tbody) return;
    clearChildren(tbody);
    if (state.iocHashes.length === 0) {
      const tr = makeEl("tr");
      const td = makeEl("td", "text-muted", "No IOC hashes configured.");
      td.colSpan = 4;
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }
    state.iocHashes.forEach(function (h) {
      const tr = makeEl("tr");
      const tdHash = makeEl("td", "mono", truncateMiddle(h.sha256, 28));
      tdHash.title = h.sha256;
      tr.appendChild(tdHash);
      tr.appendChild(makeEl("td", "", h.description || "Custom IOC"));
      tr.appendChild(makeEl("td", "mono", h.builtin ? "built-in" : "custom"));
      const tdAct = makeEl("td");
      if (h.builtin) {
        tdAct.appendChild(makeEl("span", "text-muted", "—"));
      } else {
        const rmBtn = makeEl("button", "quiet-btn update-row-btn", "Remove");
        rmBtn.type = "button";
        rmBtn.addEventListener("click", function () {
          iocAction("remove", h.sha256, "");
        });
        tdAct.appendChild(rmBtn);
      }
      tr.appendChild(tdAct);
      tbody.appendChild(tr);
    });
  }

  function iocAction(action, sha256, description) {
    return fetch("/api/actions/ioc", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify({ action: action, sha256: sha256, description: description || "" })
    }).then(function (resp) {
      if (resp.status === 401) { showLogin(); return null; }
      return resp.json().catch(function () { return { ok: false, message: "IOC update failed." }; });
    }).then(function (res) {
      if (!res) return;
      if (res.ok) {
        showToast(action === "add" ? "IOC hash added to blocklist." : "IOC hash removed.", "success");
        loadIocData();
      } else {
        showToast(res.message || "Invalid IOC hash.", "error");
      }
    }).catch(function () {
      showToast("Connection error updating IOC blocklist.", "error");
    });
  }

  function triggerScan() {
    if (state.isScanning || (state.currentData && !state.currentData.configured)) return;
    state.isScanning = true;
    const scanBtn = document.getElementById("btn-run-scan");
    if (scanBtn) {
      scanBtn.disabled = true;
      scanBtn.textContent = "Scanning...";
    }
    fetch("/api/actions/scan", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body: "{}"
    }).then(function (resp) {
      if (resp.status === 401) {
        showLogin();
        return null;
      }
      return resp.json().catch(function () { return { ok: false, message: "Scan returned HTTP " + resp.status }; });
    }).then(function (res) {
      if (res && res.ok) {
        const cnt = (res.scan && Array.isArray(res.scan.findings)) ? res.scan.findings.length : 0;
        const checked = (res.scan && res.scan.files_checked) ? res.scan.files_checked : 0;
        showToast("Scan complete: " + checked + " files checked, " + cnt + " finding(s).", cnt > 0 ? "warn" : "success");
        loadSnapshot();
      } else if (res && res.message) {
        showToast("Scan error: " + res.message, "error");
        showRefreshError("Scan error: " + res.message);
      }
    }).catch(function () {
      showRefreshError("Failed to trigger scan.");
    }).finally(function () {
      state.isScanning = false;
      if (scanBtn) {
        scanBtn.disabled = Boolean(state.currentData && !state.currentData.configured);
        scanBtn.textContent = "Scan now";
      }
    });
  }

  function toggleProtectionSetting(key, value, checkboxEl) {
    const statusEl = document.getElementById("protection-settings-status");
    if (statusEl) statusEl.textContent = "Saving...";
    if (checkboxEl) checkboxEl.disabled = true;
    const body = {};
    body[key] = Boolean(value);
    fetch("/api/actions/settings", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify(body)
    }).then(function (resp) {
      if (resp.status === 401) {
        showLogin();
        return null;
      }
      return resp.json().catch(function () { return { ok: false }; });
    }).then(function (res) {
      if (res && res.ok) {
        if (statusEl) statusEl.textContent = "Saved · Rescan to apply";
        loadSnapshot();
      } else {
        if (checkboxEl) checkboxEl.checked = !value;
        if (statusEl) statusEl.textContent = "Error";
      }
    }).catch(function () {
      if (checkboxEl) checkboxEl.checked = !value;
      if (statusEl) statusEl.textContent = "Error";
    }).finally(function () {
      if (checkboxEl) checkboxEl.disabled = false;
    });
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
    if (idEl) {
      idEl.textContent = finding.id;
      idEl.title = finding.id;
    }

    const sevEl = document.getElementById("drawer-severity");
    if (sevEl) {
      sevEl.textContent = findingSeverityLabel(finding);
      sevEl.className = "sev-badge " + findingSeverityClass(finding);
      sevEl.title = finding.assessment_state === "previous_rule"
        ? "Recorded " + finding.severity.toUpperCase() + " under the previous rule; rescan required."
        : (finding.assessment_state === "mode_only" ? "Mode-bit triage only; effective access has not been verified." : "Recorded severity");
    }

    const catEl = document.getElementById("drawer-category");
    if (catEl) {
      catEl.textContent = finding.category || "security";
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

    const qBtn = document.getElementById("drawer-quarantine-btn");
    if (qBtn) {
      const canQuarantine = finding.status === "open" && finding.category !== "permissions";
      qBtn.disabled = !canQuarantine;
      qBtn.onclick = function () {
        if (!canQuarantine) return;
        if (typeof window !== "undefined" && typeof window.confirm === "function" && !window.confirm("Move this file into Warden quarantine (0600, non-executable)?")) return;
        quarantineAction("quarantine", {
          path: finding.path,
          finding_id: finding.id,
          reason: finding.title
        });
      };
    }

    const alBtn = document.getElementById("drawer-allowlist-btn");
    if (alBtn) {
      alBtn.onclick = function () {
        const rule = (finding.evidence && finding.evidence.rule) ? finding.evidence.rule : null;
        allowlistAction("add", {
          finding_id: finding.id,
          path: finding.path,
          rule: rule,
          reason: "Ignored from dashboard"
        });
      };
    }

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
    if (viewName === "apps" && !state.appsData) {
      loadApps(false);
    }
    if (viewName === "findings") {
      loadRemediationData();
    }
    if (viewName === "coverage") {
      loadIocData();
    }
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
    const scanBtn = document.getElementById("btn-run-scan");
    if (scanBtn && !state.isScanning) {
      scanBtn.disabled = !data.configured;
    }

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
    if (state.activeView === "apps") {
      renderApps();
    }
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

    try {
      const savedTheme = typeof localStorage !== "undefined" ? localStorage.getItem("warden_theme") : null;
      applyTheme(savedTheme === "light" ? "light" : "dark");
    } catch (_e) {}

    const themeBtn = document.getElementById("btn-theme-toggle");
    if (themeBtn) {
      themeBtn.addEventListener("click", function () {
        const cur = document.documentElement ? document.documentElement.getAttribute("data-theme") : "dark";
        applyTheme(cur === "light" ? "dark" : "light");
      });
    }

    const toastClose = document.getElementById("warden-toast-close");
    if (toastClose) {
      toastClose.addEventListener("click", function () {
        const t = document.getElementById("warden-toast");
        if (t) t.classList.add("is-hidden");
      });
    }

    function performLogout() {
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
    }

    const logoutBtn = document.getElementById("btn-logout");
    if (logoutBtn) logoutBtn.addEventListener("click", performLogout);
    const mobileLogoutBtn = document.getElementById("btn-logout-mobile");
    if (mobileLogoutBtn) mobileLogoutBtn.addEventListener("click", performLogout);

    document.querySelectorAll("[data-jump-view]").forEach(function (card) {
      card.addEventListener("click", function () {
        switchView(card.getAttribute("data-jump-view"));
      });
    });

    const quickAppsBtn = document.getElementById("btn-quick-goto-apps");
    if (quickAppsBtn) {
      quickAppsBtn.addEventListener("click", function () {
        switchView("apps");
      });
    }

    const quickScanForm = document.getElementById("quick-scan-form");
    if (quickScanForm) {
      quickScanForm.addEventListener("submit", function (e) {
        e.preventDefault();
        const inp = document.getElementById("quick-scan-input");
        if (inp && inp.value.trim()) {
          runCustomTargetScan(inp.value.trim());
        }
      });
    }

    const catSelect = document.getElementById("category-select");
    if (catSelect) {
      catSelect.addEventListener("change", function () {
        state.categoryFilter = catSelect.value;
        if (state.currentData) renderFindings(state.currentData);
      });
    }

    const loadMoreBtn = document.getElementById("btn-apps-load-more");
    if (loadMoreBtn) {
      loadMoreBtn.addEventListener("click", function () {
        state.appsLimit += 200;
        renderApps();
      });
    }

    const addPathForm = document.getElementById("scope-add-path-form");
    if (addPathForm) {
      addPathForm.addEventListener("submit", function (e) {
        e.preventDefault();
        const inp = document.getElementById("scope-add-path-input");
        if (inp && inp.value.trim()) {
          mutateScope("add_path", inp.value.trim()).then(function () {
            inp.value = "";
          });
        }
      });
    }

    const addExclForm = document.getElementById("scope-add-excl-form");
    if (addExclForm) {
      addExclForm.addEventListener("submit", function (e) {
        e.preventDefault();
        const inp = document.getElementById("scope-add-excl-input");
        if (inp && inp.value.trim()) {
          mutateScope("add_exclusion", inp.value.trim()).then(function () {
            inp.value = "";
          });
        }
      });
    }

    const addIocForm = document.getElementById("ioc-add-form");
    if (addIocForm) {
      addIocForm.addEventListener("submit", function (e) {
        e.preventDefault();
        const hInp = document.getElementById("ioc-hash-input");
        const dInp = document.getElementById("ioc-desc-input");
        if (hInp && hInp.value.trim()) {
          iocAction("add", hInp.value.trim(), dInp ? dInp.value.trim() : "").then(function () {
            hInp.value = "";
            if (dInp) dInp.value = "";
          });
        }
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

    const historyBtn = document.getElementById("overview-history-btn");
    if (historyBtn) historyBtn.addEventListener("click", function () {
      state.statusFilter = "open";
      state.severityFilter = "review";
      const severitySelect = document.getElementById("severity-select");
      if (severitySelect) severitySelect.value = "review";
      switchView("findings");
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
            submitBtn.textContent = "Unlock console";
          }
        });
      });
    }

    const scanBtn = document.getElementById("btn-run-scan");
    if (scanBtn) {
      scanBtn.addEventListener("click", triggerScan);
    }

    const checkUpdBtn = document.getElementById("btn-check-updates");
    if (checkUpdBtn) {
      checkUpdBtn.addEventListener("click", function () {
        loadApps(true);
        loadSnapshot();
      });
    }

    const updAllPlugBtn = document.getElementById("btn-update-all-plugins");
    if (updAllPlugBtn) {
      updAllPlugBtn.addEventListener("click", function () {
        if (typeof window !== "undefined" && typeof window.confirm === "function" && !window.confirm("Update all installed Hermes plugins?")) return;
        triggerUpdate("hermes_plugins_all", null, updAllPlugBtn);
      });
    }

    const updOsAllBtn = document.getElementById("btn-update-os-all");
    if (updOsAllBtn) {
      updOsAllBtn.addEventListener("click", function () {
        if (typeof window !== "undefined" && typeof window.confirm === "function" && !window.confirm("Run OS package updates (or show the terminal update command)?")) return;
        triggerUpdate("os_all", null, updOsAllBtn);
      });
    }

    const appsBannerClose = document.getElementById("apps-action-close-btn");
    if (appsBannerClose) {
      appsBannerClose.addEventListener("click", function () {
        const b = document.getElementById("apps-action-banner");
        if (b) b.classList.add("is-hidden");
      });
    }

    document.querySelectorAll("[data-apps-filter]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        state.appsFilter = btn.getAttribute("data-apps-filter");
        renderApps();
      });
    });

    const appsSearch = document.getElementById("apps-search");
    if (appsSearch) {
      appsSearch.addEventListener("input", function () {
        state.appsSearch = appsSearch.value;
        renderApps();
      });
    }

    const tSec = document.getElementById("toggle-security-scan");
    if (tSec) {
      tSec.addEventListener("change", function () {
        toggleProtectionSetting("security_scan", tSec.checked, tSec);
      });
    }
    const tAv = document.getElementById("toggle-system-av");
    if (tAv) {
      tAv.addEventListener("change", function () {
        toggleProtectionSetting("use_system_av", tAv.checked, tAv);
      });
    }
    const tPerm = document.getElementById("toggle-check-permissions");
    if (tPerm) {
      tPerm.addEventListener("change", function () {
        toggleProtectionSetting("check_permissions", tPerm.checked, tPerm);
      });
    }

    document.addEventListener("keydown", function (e) {
      const loginOverlay = document.getElementById("login-screen");
      if (loginOverlay && !loginOverlay.classList.contains("is-hidden")) {
        return;
      }
      const tag = (e.target && e.target.tagName) ? e.target.tagName.toLowerCase() : "";
      const inInput = tag === "input" || tag === "select" || tag === "textarea" || Boolean(e.target && e.target.isContentEditable);

      if (e.key === "Escape") {
        if (state.selectedFindingId) {
          closeDrawer();
          return;
        }
      }

      if (!inInput && !e.ctrlKey && !e.metaKey && !e.altKey) {
        const num = parseInt(e.key, 10);
        if (num >= 1 && num <= VIEW_KEYS.length) {
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
    root.CustodianUI.renderApps = renderApps;
    root.CustodianUI.showAppsActionBanner = showAppsActionBanner;
    root.CustodianUI.renderProfiles = renderProfiles;
    root.CustodianUI.renderCoverage = renderCoverage;
    root.CustodianUI.renderHealth = renderHealth;
    root.CustodianUI.renderAll = renderAll;
    root.CustodianUI.state = state;
  }

  document.addEventListener("DOMContentLoaded", initApp);
})(typeof globalThis !== "undefined" ? globalThis : window);
