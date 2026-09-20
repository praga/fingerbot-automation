/**
 * Tuya Fingerbot Automation Dashboard Client
 * Responsive, mobile-friendly implementation with live dual countdowns.
 */

const API_BASE = "";
let currentStatus = null;
let currentConfig = null;
let pollTimer = null;
let countdownLocalTimer = null;

// Countdown tracking
let localNextPressSeconds = null;
let totalIntervalSeconds = 660; // 11 * 60

let localSessionSeconds = null;
let totalSessionSeconds = 0;

// Configured values
let selectedIntervalMins = 11;
let selectedDurationHours = 0; // 0 = continuous (None)

// DOM Elements: Header & Status
const navMacDisplay = document.getElementById("navMacDisplay");
const navRssiBadge = document.getElementById("navRssiBadge");
const bleDot = document.getElementById("bleDot");
const activeStateBadge = document.getElementById("activeStateBadge");
const activeStateText = document.getElementById("activeStateText");

// Next Press Countdown Hero
const countdownDisplay = document.getElementById("countdownDisplay");
const countdownCircle = document.getElementById("countdownCircle");
const nextRunTimestamp = document.getElementById("nextRunTimestamp");

// Session Auto-Stop Info Banner
const sessionStopBanner = document.getElementById("sessionStopBanner");
const sessionCountdownDisplay = document.getElementById("sessionCountdownDisplay");
const sessionStopTimestamp = document.getElementById("sessionStopTimestamp");
const sessionDurationTag = document.getElementById("sessionDurationTag");
const sessionProgressBar = document.getElementById("sessionProgressBar");
const sessionModeBadge = document.getElementById("sessionModeBadge");

// Buttons
const toggleAutomationBtn = document.getElementById("toggleAutomationBtn");
const toggleBtnIcon = document.getElementById("toggleBtnIcon");
const toggleBtnLabel = document.getElementById("toggleBtnLabel");
const triggerNowBtn = document.getElementById("triggerNowBtn");

// Interval Elements
const intervalPresetBtns = document.querySelectorAll(".preset-btn");
const customIntervalRow = document.getElementById("customIntervalRow");
const customIntervalInput = document.getElementById("customIntervalInput");
const intervalSummaryText = document.getElementById("intervalSummaryText");

// Duration Elements
const durationBtns = document.querySelectorAll(".duration-btn");
const customDurationRow = document.getElementById("customDurationRow");
const customDurationInput = document.getElementById("customDurationInput");
const durationSummaryText = document.getElementById("durationSummaryText");

// Metrics
const metricTotalPresses = document.getElementById("metricTotalPresses");
const metricFailedPresses = document.getElementById("metricFailedPresses");
const metricLastPressTime = document.getElementById("metricLastPressTime");
const metricBleState = document.getElementById("metricBleState");
const metricBleDot = document.getElementById("metricBleDot");

// Spec display
const dispDeviceName = document.getElementById("dispDeviceName");
const dispDeviceMac = document.getElementById("dispDeviceMac");
const dispArmDuration = document.getElementById("dispArmDuration");
const dispPressesPerCycle = document.getElementById("dispPressesPerCycle");
const dispActiveHours = document.getElementById("dispActiveHours");

// Activity logs
const logsContainer = document.getElementById("logsContainer");
const clearLogsBtn = document.getElementById("clearLogsBtn");

// Settings Modal
const settingsModal = document.getElementById("settingsModal");
const openSettingsBtn = document.getElementById("openSettingsBtn");
const closeSettingsBtn = document.getElementById("closeSettingsBtn");
const cancelSettingsBtn = document.getElementById("cancelSettingsBtn");
const settingsForm = document.getElementById("settingsForm");
const cfgActiveHoursToggle = document.getElementById("cfgActiveHoursToggle");
const activeHoursRow = document.getElementById("activeHoursRow");

// Scan Modal
const scanModal = document.getElementById("scanModal");
const closeScanBtn = document.getElementById("closeScanBtn");
const scanBtn = document.getElementById("scanBtn");
const modalScanBtn = document.getElementById("modalScanBtn");
const scanStatusMsg = document.getElementById("scanStatusMsg");
const scanResultsList = document.getElementById("scanResultsList");

// SVG Circle Circumference for r=54: 2 * Math.PI * 54 = 339.292
const CIRCUMFERENCE = 2 * Math.PI * 54;
if (countdownCircle) {
  countdownCircle.style.strokeDasharray = CIRCUMFERENCE;
  countdownCircle.style.strokeDashoffset = 0;
}

// Initialize
document.addEventListener("DOMContentLoaded", () => {
  setupEventListeners();
  fetchStatus();
  fetchLogs();

  pollTimer = setInterval(fetchStatus, 1500);
  setInterval(fetchLogs, 4000);
  countdownLocalTimer = setInterval(tickLocalCountdowns, 1000);
});

let hasInitializedControls = false;

function syncControlsFromStatus(s) {
  if (hasInitializedControls) return;
  hasInitializedControls = true;

  // 1. Sync Interval
  if (s.interval_minutes) {
    selectedIntervalMins = s.interval_minutes;
    totalIntervalSeconds = s.interval_minutes * 60;
    if (customIntervalInput) customIntervalInput.value = s.interval_minutes;

    let matched = false;
    intervalPresetBtns.forEach(btn => {
      if (parseFloat(btn.dataset.min) === s.interval_minutes) {
        btn.classList.add("active");
        matched = true;
      } else {
        btn.classList.remove("active");
      }
    });

    if (!matched) {
      const customBtn = document.querySelector('.preset-btn[data-min="custom"]');
      if (customBtn) customBtn.classList.add("active");
      if (customIntervalRow) customIntervalRow.style.display = "flex";
    }
  }

  // 2. Sync Duration
  if (s.stop_after_hours !== undefined) {
    selectedDurationHours = s.stop_after_hours && s.stop_after_hours > 0 ? s.stop_after_hours : 0;
    if (selectedDurationHours > 0 && customDurationInput) {
      customDurationInput.value = selectedDurationHours;
    }

    let matched = false;
    durationBtns.forEach(btn => {
      const bHours = parseFloat(btn.dataset.hours);
      if ((selectedDurationHours === 0 && bHours === 0) || (selectedDurationHours > 0 && bHours === selectedDurationHours)) {
        btn.classList.add("active");
        matched = true;
      } else {
        btn.classList.remove("active");
      }
    });

    if (!matched && selectedDurationHours > 0) {
      const customBtn = document.querySelector('.duration-btn[data-hours="custom"]');
      if (customBtn) customBtn.classList.add("active");
      if (customDurationRow) customDurationRow.style.display = "flex";
    }
  }

  updateIntervalSummary();
  updateDurationSummary();
  updateCountdownsView();
}

let updateDebounceTimer = null;
function triggerLiveUpdate() {
  updateIntervalSummary();
  updateDurationSummary();
  updateCountdownsView();

  if (!currentStatus || !currentStatus.is_running) return;

  clearTimeout(updateDebounceTimer);
  updateDebounceTimer = setTimeout(async () => {
    try {
      const stopHours = selectedDurationHours > 0 ? selectedDurationHours : null;
      const res = await fetch(`${API_BASE}/api/automation/update`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          interval_minutes: selectedIntervalMins,
          stop_after_hours: stopHours
        })
      });
      const data = await res.json();
      if (data.data) {
        currentStatus = data.data;
        renderStatus(data.data);
      }
    } catch (err) {
      console.error("Failed to update running automation:", err);
    }
  }, 250);
}

function setupEventListeners() {
  // Interval Presets
  intervalPresetBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      intervalPresetBtns.forEach(b => b.classList.remove("active"));
      btn.classList.add("active");

      const minsAttr = btn.dataset.min;
      if (minsAttr === "custom") {
        if (customIntervalRow) {
          customIntervalRow.style.display = "flex";
          customIntervalInput.focus();
        }
        selectedIntervalMins = parseFloat(customIntervalInput.value) || 11;
      } else {
        if (customIntervalRow) customIntervalRow.style.display = "none";
        selectedIntervalMins = parseFloat(minsAttr);
        if (customIntervalInput) customIntervalInput.value = selectedIntervalMins;
      }
      totalIntervalSeconds = selectedIntervalMins * 60;
      triggerLiveUpdate();
    });
  });

  if (customIntervalInput) {
    customIntervalInput.addEventListener("input", () => {
      const val = parseFloat(customIntervalInput.value);
      if (!val || val <= 0) return;
      selectedIntervalMins = val;
      totalIntervalSeconds = val * 60;
      triggerLiveUpdate();
    });
  }

  // Duration Presets (Stop After)
  durationBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      durationBtns.forEach(b => b.classList.remove("active"));
      btn.classList.add("active");

      const hoursAttr = btn.dataset.hours;
      if (hoursAttr === "custom") {
        if (customDurationRow) {
          customDurationRow.style.display = "flex";
          customDurationInput.focus();
        }
        selectedDurationHours = parseFloat(customDurationInput.value) || 1;
      } else {
        if (customDurationRow) customDurationRow.style.display = "none";
        selectedDurationHours = parseFloat(hoursAttr);
      }
      triggerLiveUpdate();
    });
  });

  if (customDurationInput) {
    customDurationInput.addEventListener("input", () => {
      const val = parseFloat(customDurationInput.value);
      if (isNaN(val) || val < 0) return;
      selectedDurationHours = val;
      triggerLiveUpdate();
    });
  }

  // Start / Stop Toggle
  toggleAutomationBtn.addEventListener("click", handleToggleAutomation);

  // Trigger Now
  triggerNowBtn.addEventListener("click", handleTriggerNow);

  // Clear Logs
  clearLogsBtn.addEventListener("click", handleClearLogs);

  // Settings Modal Handlers
  openSettingsBtn.addEventListener("click", openSettings);
  closeSettingsBtn.addEventListener("click", () => settingsModal.classList.remove("open"));
  cancelSettingsBtn.addEventListener("click", () => settingsModal.classList.remove("open"));
  settingsForm.addEventListener("submit", handleSaveSettings);

  // Backdrop dismiss
  settingsModal.addEventListener("click", (e) => {
    if (e.target === settingsModal) settingsModal.classList.remove("open");
  });
  scanModal.addEventListener("click", (e) => {
    if (e.target === scanModal) scanModal.classList.remove("open");
  });

  cfgActiveHoursToggle.addEventListener("change", () => {
    activeHoursRow.style.display = cfgActiveHoursToggle.checked ? "grid" : "none";
  });

  // Scan Handlers
  scanBtn.addEventListener("click", handleScanBle);
  modalScanBtn.addEventListener("click", handleScanBle);
  closeScanBtn.addEventListener("click", () => scanModal.classList.remove("open"));
}

function updateIntervalSummary() {
  if (intervalSummaryText) {
    intervalSummaryText.textContent = `Every ${selectedIntervalMins} min`;
  }
}

function updateDurationSummary() {
  if (!durationSummaryText) return;
  if (selectedDurationHours === 0 || selectedDurationHours === null) {
    durationSummaryText.textContent = "Continuous";
  } else if (selectedDurationHours < 1) {
    durationSummaryText.textContent = `${Math.round(selectedDurationHours * 60)} min limit`;
  } else {
    durationSummaryText.textContent = `${selectedDurationHours} hour${selectedDurationHours > 1 ? 's' : ''}`;
  }
}

async function fetchStatus() {
  try {
    const res = await fetch(`${API_BASE}/api/status`);
    if (!res.ok) return;
    const data = await res.json();
    currentStatus = data;
    renderStatus(data);
  } catch (err) {
    console.warn("Status fetch error:", err);
  }
}

async function fetchLogs() {
  try {
    const res = await fetch(`${API_BASE}/api/logs`);
    if (!res.ok) return;
    const data = await res.json();
    renderLogs(data.logs || []);
  } catch (err) {
    console.warn("Logs fetch error:", err);
  }
}

function renderStatus(s) {
  syncControlsFromStatus(s);

  // Tuya Local Key banner toggle
  const keyWarningBanner = document.getElementById("keyWarningBanner");
  if (keyWarningBanner) {
    keyWarningBanner.style.display = s.has_local_key ? "none" : "flex";
  }

  // Nav
  navMacDisplay.textContent = s.device_mac;
  navRssiBadge.textContent = s.last_rssi ? `${s.last_rssi} dBm` : "N/A";

  // Dot color
  bleDot.className = "dot";
  if (metricBleDot) metricBleDot.className = "dot-sm";

  if (s.ble_is_busy) {
    bleDot.classList.add("amber");
    if (metricBleDot) {
      metricBleDot.style.background = "var(--warning)";
      metricBleDot.style.boxShadow = "0 0 6px var(--warning)";
    }
  } else if (s.failed_presses > 0 && s.total_presses === 0) {
    bleDot.classList.add("red");
    if (metricBleDot) {
      metricBleDot.style.background = "var(--danger)";
      metricBleDot.style.boxShadow = "0 0 6px var(--danger)";
    }
  } else {
    bleDot.classList.add("green");
    if (metricBleDot) {
      metricBleDot.style.background = "var(--success)";
      metricBleDot.style.boxShadow = "0 0 6px var(--success)";
    }
  }

  // Active state & Start/Stop buttons
  if (s.is_running) {
    activeStateBadge.className = "active-badge running";
    activeStateText.textContent = "AUTOMATION RUNNING";

    toggleAutomationBtn.className = "btn btn-primary btn-large running";
    toggleBtnLabel.textContent = "STOP AUTOMATION";
    toggleBtnIcon.innerHTML = `<rect x="6" y="6" width="12" height="12"></rect>`;
  } else {
    activeStateBadge.className = "active-badge";
    activeStateText.textContent = "STOPPED";

    toggleAutomationBtn.className = "btn btn-primary btn-large";
    toggleBtnLabel.textContent = "START AUTOMATION";
    toggleBtnIcon.innerHTML = `<polygon points="5 3 19 12 5 21 5 3"></polygon>`;
  }

  // Interval countdown sync
  if (s.is_running && s.seconds_remaining !== null) {
    localNextPressSeconds = s.seconds_remaining;
    totalIntervalSeconds = s.interval_minutes * 60;
  } else if (!s.is_running) {
    localNextPressSeconds = null;
  }

  // Auto-stop countdown sync
  if (s.is_running && s.session_seconds_remaining !== null) {
    localSessionSeconds = s.session_seconds_remaining;
    if (s.stop_after_hours) {
      totalSessionSeconds = s.stop_after_hours * 3600;
    }
    sessionStopBanner.style.display = "flex";
    if (sessionDurationTag) {
      const tagText = s.stop_after_hours < 1 ? `${Math.round(s.stop_after_hours * 60)}m Session` : `${s.stop_after_hours}h Session`;
      sessionDurationTag.textContent = tagText;
    }
    if (sessionStopTimestamp && s.stop_at) {
      const stopDate = new Date(s.stop_at);
      sessionStopTimestamp.textContent = `Auto-stops at ${stopDate.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`;
    }
    if (sessionModeBadge) {
      const badgeText = s.stop_after_hours < 1 ? `${Math.round(s.stop_after_hours * 60)}m Limit` : `${s.stop_after_hours}h Limit`;
      sessionModeBadge.textContent = badgeText;
    }
  } else {
    localSessionSeconds = null;
    sessionStopBanner.style.display = "none";
    if (sessionModeBadge) {
      sessionModeBadge.textContent = selectedDurationHours > 0
        ? (selectedDurationHours < 1 ? `${Math.round(selectedDurationHours * 60)}m Limit` : `${selectedDurationHours}h Limit`)
        : "Continuous";
    }
  }

  // Metrics
  metricTotalPresses.textContent = s.total_presses;
  metricFailedPresses.textContent = s.failed_presses;
  metricLastPressTime.textContent = s.last_press_time
    ? new Date(s.last_press_time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
    : "Never";
  metricBleState.textContent = s.ble_status;

  // Device specs
  dispDeviceName.textContent = s.device_name;
  dispDeviceMac.textContent = s.device_mac;
  dispArmDuration.textContent = `${s.arm_duration_seconds}s`;
  if (dispPressesPerCycle) {
    dispPressesPerCycle.textContent = `${s.presses_per_cycle || 2}x (${s.repeat_delay_seconds || 5.0}s delay)`;
  }
  dispActiveHours.textContent = s.active_hours_enabled
    ? `${s.active_hours_start} - ${s.active_hours_end}`
    : "24/7 (Always Active)";

  updateCountdownsView();
}

function tickLocalCountdowns() {
  if (localNextPressSeconds !== null && localNextPressSeconds > 0) {
    localNextPressSeconds--;
  }

  if (localSessionSeconds !== null && localSessionSeconds > 0) {
    localSessionSeconds--;
  }

  updateCountdownsView();
}

function updateCountdownsView() {
  // 1. Next Press Countdown
  if (!currentStatus || !currentStatus.is_running || localNextPressSeconds === null) {
    countdownDisplay.textContent = "--:--";
    const durText = selectedDurationHours > 0 
      ? (selectedDurationHours < 1 ? `${Math.round(selectedDurationHours * 60)}m auto-stop` : `${selectedDurationHours}h auto-stop`)
      : "Continuous";
    nextRunTimestamp.textContent = `Ready • Every ${selectedIntervalMins}m • ${durText}`;
    if (countdownCircle) countdownCircle.style.strokeDashoffset = 0;
  } else {
    const mins = Math.floor(localNextPressSeconds / 60);
    const secs = localNextPressSeconds % 60;
    countdownDisplay.textContent = `${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;

    if (currentStatus.next_run_time) {
      const nextDate = new Date(currentStatus.next_run_time);
      nextRunTimestamp.textContent = `Next at ${nextDate.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}`;
    }

    if (countdownCircle && totalIntervalSeconds > 0) {
      const progress = Math.min(1, Math.max(0, localNextPressSeconds / totalIntervalSeconds));
      countdownCircle.style.strokeDashoffset = CIRCUMFERENCE * (1 - progress);
    }
  }

  // 2. Session Auto-Stop Countdown
  if (localSessionSeconds !== null && sessionCountdownDisplay) {
    const hrs = Math.floor(localSessionSeconds / 3600);
    const remMins = Math.floor((localSessionSeconds % 3600) / 60);
    const remSecs = localSessionSeconds % 60;

    sessionCountdownDisplay.textContent = `${String(hrs).padStart(2, '0')}:${String(remMins).padStart(2, '0')}:${String(remSecs).padStart(2, '0')}`;

    if (sessionProgressBar && totalSessionSeconds > 0) {
      const elapsed = Math.max(0, totalSessionSeconds - localSessionSeconds);
      const pct = Math.min(100, Math.round((elapsed / totalSessionSeconds) * 100));
      sessionProgressBar.style.width = `${pct}%`;
    }
  }
}

async function handleToggleAutomation() {
  if (!currentStatus) return;

  if (currentStatus.is_running) {
    try {
      toggleAutomationBtn.disabled = true;
      const res = await fetch(`${API_BASE}/api/automation/stop`, { method: "POST" });
      const data = await res.json();
      if (data.data) renderStatus(data.data);
    } catch (err) {
      alert("Failed to stop automation: " + err);
    } finally {
      toggleAutomationBtn.disabled = false;
    }
  } else {
    const intervalMins = selectedIntervalMins;
    const stopHours = selectedDurationHours > 0 ? selectedDurationHours : null;

    try {
      toggleAutomationBtn.disabled = true;
      const res = await fetch(`${API_BASE}/api/automation/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          interval_minutes: intervalMins,
          stop_after_hours: stopHours
        })
      });
      const data = await res.json();
      if (data.data) renderStatus(data.data);
    } catch (err) {
      alert("Failed to start automation: " + err);
    } finally {
      toggleAutomationBtn.disabled = false;
    }
  }
}

async function handleTriggerNow() {
  if (currentStatus && !currentStatus.has_local_key) {
    alert("Tuya Local Key Required:\n\nYour Fingerbot is paired with SmartLife and requires its 16-character Local Key to authorize motor movement.\n\nPlease enter your key in the Settings dialog.");
    openSettings();
    setTimeout(() => {
      const keyInput = document.getElementById("cfgLocalKey");
      if (keyInput) keyInput.focus();
    }, 350);
    return;
  }

  const originalHtml = triggerNowBtn.innerHTML;
  try {
    triggerNowBtn.disabled = true;
    triggerNowBtn.className = "btn btn-secondary btn-large btn-pressing";
    triggerNowBtn.innerHTML = `<span class="spinner-sm"></span> <span>PRESSING...</span>`;

    const res = await fetch(`${API_BASE}/api/trigger`, { method: "POST" });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: "Device actuation failed" }));
      triggerNowBtn.className = "btn btn-secondary btn-large btn-pressed-fail";
      triggerNowBtn.innerHTML = `<span>✕ FAILED</span>`;
      alert("Trigger failed: " + (err.detail || "Fingerbot did not respond"));
      if (err.detail && err.detail.toLowerCase().includes("local key")) {
        openSettings();
        setTimeout(() => {
          const keyInput = document.getElementById("cfgLocalKey");
          if (keyInput) keyInput.focus();
        }, 350);
      }
      return;
    }

    triggerNowBtn.className = "btn btn-secondary btn-large btn-pressed-success";
    triggerNowBtn.innerHTML = `<span>✓ PRESSED!</span>`;
    fetchStatus();
    setTimeout(fetchLogs, 800);
  } catch (err) {
    triggerNowBtn.className = "btn btn-secondary btn-large btn-pressed-fail";
    triggerNowBtn.innerHTML = `<span>✕ ERROR</span>`;
    alert("Error triggering Fingerbot: " + err);
  } finally {
    setTimeout(() => {
      triggerNowBtn.disabled = false;
      triggerNowBtn.className = "btn btn-secondary btn-large";
      triggerNowBtn.innerHTML = originalHtml;
    }, 2200);
  }
}

function renderLogs(logs) {
  if (!logsContainer) return;

  if (!logs || logs.length === 0) {
    logsContainer.innerHTML = `<div class="empty-cell">No execution logs yet. Click "Press Now" or start automation to begin.</div>`;
    return;
  }

  logsContainer.innerHTML = logs.map(l => {
    const timeStr = new Date(l.timestamp).toLocaleTimeString([], {
      hour: '2-digit', minute: '2-digit', second: '2-digit'
    });
    const isSuccess = l.success;
    const badgeClass = isSuccess ? "badge-success" : "badge-error";
    const badgeText = isSuccess ? "SUCCESS" : "ERROR";
    const details = l.details?.duration_seconds ? `${l.details.duration_seconds}s` : (l.details?.hours ? `${l.details.hours}h auto-stop` : (l.details?.target_mac || ""));

    return `
      <div class="log-entry-card ${isSuccess ? 'log-success' : 'log-error'}">
        <div class="log-entry-header">
          <div class="log-entry-left">
            <span class="badge ${badgeClass}">${badgeText}</span>
            <span class="log-time font-mono">${timeStr}</span>
          </div>
          ${details ? `<span class="log-detail-tag font-mono">${escapeHtml(details)}</span>` : ''}
        </div>
        <div class="log-entry-msg">
          ${escapeHtml(l.message)}
        </div>
      </div>
    `;
  }).join("");
}

async function handleClearLogs() {
  if (!confirm("Clear all execution logs?")) return;
  try {
    await fetch(`${API_BASE}/api/logs/clear`, { method: "POST" });
    fetchLogs();
  } catch (err) {
    alert("Error clearing logs: " + err);
  }
}

// Settings Modal
async function openSettings() {
  try {
    const res = await fetch(`${API_BASE}/api/config`);
    if (!res.ok) return;
    currentConfig = await res.json();

    document.getElementById("cfgDeviceMac").value = currentConfig.device_mac || "";
    document.getElementById("cfgDeviceName").value = currentConfig.device_name || "";
    document.getElementById("cfgLocalKey").value = currentConfig.local_key || "";
    if (document.getElementById("cfgDeviceId")) document.getElementById("cfgDeviceId").value = currentConfig.device_id || "";
    document.getElementById("cfgArmDuration").value = currentConfig.arm_duration_seconds || 1.0;
    if (document.getElementById("cfgPressesPerCycle")) {
      document.getElementById("cfgPressesPerCycle").value = currentConfig.presses_per_cycle || 2;
    }
    if (document.getElementById("cfgRepeatDelay")) {
      document.getElementById("cfgRepeatDelay").value = currentConfig.repeat_delay_seconds || 5.0;
    }
    cfgActiveHoursToggle.checked = !!currentConfig.active_hours_enabled;
    activeHoursRow.style.display = cfgActiveHoursToggle.checked ? "grid" : "none";
    document.getElementById("cfgStartTime").value = currentConfig.active_hours_start || "08:00";
    document.getElementById("cfgEndTime").value = currentConfig.active_hours_end || "22:00";
    document.getElementById("cfgAutoStartToggle").checked = !!currentConfig.auto_start_on_boot;

    settingsModal.classList.add("open");
  } catch (err) {
    alert("Error loading config: " + err);
  }
}

async function handleSaveSettings(e) {
  e.preventDefault();
  const payload = {
    ...currentConfig,
    device_mac: document.getElementById("cfgDeviceMac").value.trim().toUpperCase(),
    device_name: document.getElementById("cfgDeviceName").value.trim(),
    local_key: document.getElementById("cfgLocalKey").value.trim(),
    device_id: document.getElementById("cfgDeviceId") ? document.getElementById("cfgDeviceId").value.trim() : "",
    arm_duration_seconds: parseFloat(document.getElementById("cfgArmDuration").value) || 1.0,
    presses_per_cycle: parseInt(document.getElementById("cfgPressesPerCycle")?.value) || 2,
    repeat_delay_seconds: parseFloat(document.getElementById("cfgRepeatDelay")?.value) || 5.0,
    active_hours_enabled: cfgActiveHoursToggle.checked,
    active_hours_start: document.getElementById("cfgStartTime").value,
    active_hours_end: document.getElementById("cfgEndTime").value,
    auto_start_on_boot: document.getElementById("cfgAutoStartToggle").checked
  };

  try {
    const res = await fetch(`${API_BASE}/api/config`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    if (!res.ok) throw new Error("Failed to save");
    settingsModal.classList.remove("open");
    fetchStatus();
  } catch (err) {
    alert("Error saving settings: " + err);
  }
}

// BLE Scanner
async function handleScanBle() {
  scanModal.classList.add("open");
  scanStatusMsg.textContent = "Scanning nearby BLE devices (4s)...";
  scanResultsList.innerHTML = `<div style="text-align: center; padding: 20px; color: var(--text-muted);">Please wait, searching frequencies...</div>`;

  try {
    const res = await fetch(`${API_BASE}/api/scan`);
    if (!res.ok) {
      const err = await res.json();
      scanStatusMsg.textContent = "Scan error: " + (err.detail || "Unable to scan");
      return;
    }
    const data = await res.json();
    const devices = data.devices || [];

    if (devices.length === 0) {
      scanStatusMsg.textContent = "No devices detected nearby.";
      scanResultsList.innerHTML = "";
      return;
    }

    scanStatusMsg.textContent = `Found ${devices.length} devices. Click any device to select it:`;
    scanResultsList.innerHTML = devices.map(d => `
      <div class="scan-item" onclick="selectScannedDevice('${d.address}', '${escapeHtml(d.name)}')">
        <div class="scan-item-info">
          <span class="scan-item-name">${d.is_target ? '★ ' : ''}${escapeHtml(d.name || 'Unknown')}</span>
          <span class="scan-item-mac font-mono">${d.address}</span>
        </div>
        <span class="rssi-badge font-mono">${d.rssi} dBm</span>
      </div>
    `).join("");
  } catch (err) {
    scanStatusMsg.textContent = "Scan failed: " + err;
  }
}

window.selectScannedDevice = function(mac, name) {
  document.getElementById("cfgDeviceMac").value = mac;
  if (name && name !== "Unknown") {
    document.getElementById("cfgDeviceName").value = name;
  }
  scanModal.classList.remove("open");
  if (!settingsModal.classList.contains("open")) {
    openSettings();
  }
};

function escapeHtml(str) {
  return String(str || "").replace(/[&<>"']/g, m => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[m]);
}
