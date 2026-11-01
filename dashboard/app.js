// litds dashboard app logic — split out of index.html once the file grew
// past comfortable single-file size (UI/UX pass: hamburger nav, employee
// profile as a real bookmarkable route, visual polish).
//
// Deliberately still plain, framework-free JS with no build step, not a
// React/Vue rewrite -- weighed explicitly as part of that pass. This
// project's whole packaging story (packaging/README.md) is built around
// "Python 3.10+ and nothing else" on the admin's machine; the dashboard is
// served directly from disk via FastAPI's FileResponse/StaticFiles with no
// compilation step. A framework's build step doesn't burden the admin
// directly (it runs at release time, not install time) UNLESS the built
// output is committed to the repo -- which would break from this project's
// existing pattern of never committing packaging build output (see
// .gitignore, and how packaging/agent/build_agent.ps1 builds fresh rather
// than shipping a committed .exe). Staying consistent with that pattern
// would mean requiring Node.js as a NEW install-time prerequisite just to
// run `npm run build` before the admin's first launch -- a real regression
// against the "lightweight, SME-appropriate" framing that drove every
// other dependency decision in this project (see docs/known_limitations.md:
// SQLite over PostgreSQL, a custom lightweight agent over Filebeat/Wazuh).
// The actual ask here -- better navigation, a real profile route, visual
// polish -- is a presentation/navigation problem, not a complex-client-
// state problem, so it doesn't need a framework's reactivity to solve well.
// Real cost of this choice, stated plainly: the router and nav drawer below
// are hand-rolled rather than free from a framework -- more code here, not
// zero, just less than a whole new toolchain would cost the install story.
//
// No WebSocket exists yet (backend/main.py explicitly defers it) -- live
// updates are REST polling (every 5s) instead of a push feed. Swap in a
// real WS client later without touching the render*() functions below;
// they only care about the data shape.

/* ─────────────────────────────────────────────
   Auth
   ───────────────────────────────────────────── */
// Token in localStorage is XSS-readable — an accepted tradeoff for this
// internal-tool context, not an implicit default. See docs/known_limitations.md.
let token = localStorage.getItem('litds_token');
let pollHandle = null;
// Overview extras (charts + system-health strip) poll separately from
// refreshAll's 5s cadence -- see refreshOverviewExtras's own comment for
// why (a live LM Studio reachability probe every 5s would be wasteful and
// adds latency risk to a poll that's otherwise pure DB reads).
let overviewPollHandle = null;
// Risk-history (sparkline) poll, also separate from refreshAll's 5s
// cadence -- see refreshRiskHistory's own comment for why.
let riskHistoryPollHandle = null;

function authHeaders() {
  return token ? { 'Authorization': `Bearer ${token}` } : {};
}

// Used specifically for the uploaded policy document's converted text
// (the Company Profile page's viewer, loadCompanyPage) -- the one place
// this app renders a large blob of externally-sourced free text
// (extracted from an admin-uploaded PDF) into innerHTML, so it's escaped
// rather than trusted the way this
// app's own short, structured server fields (titles, usernames, reasons)
// are elsewhere.
function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text == null ? '' : text;
  return div.innerHTML;
}

async function authFetch(path, opts = {}) {
  const res = await fetch(path, {
    ...opts,
    headers: { ...(opts.headers || {}), ...authHeaders(), 'Content-Type': 'application/json' },
  });
  if (res.status === 401) {
    logout();
    throw new Error('unauthorized');
  }
  return res;
}

function showAuthError(msg) {
  const el = document.getElementById('authError');
  el.textContent = msg;
  el.style.display = 'block';
}
function clearAuthError() {
  document.getElementById('authError').style.display = 'none';
}
function showLogin() {
  clearAuthError();
  document.getElementById('loginForm').classList.remove('hidden');
  document.getElementById('registerForm').classList.add('hidden');
}
function showRegister() {
  clearAuthError();
  document.getElementById('loginForm').classList.add('hidden');
  document.getElementById('registerForm').classList.remove('hidden');
}

async function doLogin() {
  clearAuthError();
  const username = document.getElementById('loginUsername').value.trim();
  const password = document.getElementById('loginPassword').value;
  try {
    const res = await fetch('/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      showAuthError(err.detail || 'Login failed');
      return;
    }
    const data = await res.json();
    token = data.access_token;
    localStorage.setItem('litds_token', token);
    enterApp();
  } catch (e) {
    showAuthError('Could not reach the server');
  }
}

async function doRegister() {
  clearAuthError();
  const company_name = document.getElementById('regCompanyName').value.trim();
  const admin_username = document.getElementById('regUsername').value.trim();
  const admin_password = document.getElementById('regPassword').value;
  try {
    const res = await fetch('/company/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ company_name, admin_username, admin_password }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      showAuthError(err.detail || 'Registration failed');
      return;
    }
    // company_code is shown once here; also always retrievable later via
    // GET /company/me once logged in.
    document.getElementById('loginUsername').value = admin_username;
    document.getElementById('loginPassword').value = '';
    showLogin();
    showAuthError('Company created — sign in with your new credentials.');
    document.getElementById('authError').style.background = 'rgba(79,150,104,.14)';
    document.getElementById('authError').style.borderColor = 'var(--low)';
    document.getElementById('authError').style.color = 'var(--low)';
  } catch (e) {
    showAuthError('Could not reach the server');
  }
}

function logout() {
  token = null;
  localStorage.removeItem('litds_token');
  if (pollHandle) { clearInterval(pollHandle); pollHandle = null; }
  if (overviewPollHandle) { clearInterval(overviewPollHandle); overviewPollHandle = null; }
  if (riskHistoryPollHandle) { clearInterval(riskHistoryPollHandle); riskHistoryPollHandle = null; }
  closeNav();
  document.getElementById('appScreen').classList.add('hidden');
  document.getElementById('authScreen').classList.remove('hidden');
  showLogin();
}

async function enterApp() {
  document.getElementById('authScreen').classList.add('hidden');
  document.getElementById('appScreen').classList.remove('hidden');
  // Restore whichever view the URL specifies BEFORE the first data load --
  // a direct load/refresh on a deep-linked #/employees/{id} URL should
  // land straight on that profile, not flash the dashboard first. Router
  // is defined further down (Routing section).
  await routeFromHash();
  await refreshAll();
  if (pollHandle) clearInterval(pollHandle);
  pollHandle = setInterval(refreshAll, 5000); // no WebSocket yet — see file header comment

  await refreshOverviewExtras();
  if (overviewPollHandle) clearInterval(overviewPollHandle);
  overviewPollHandle = setInterval(refreshOverviewExtras, OVERVIEW_EXTRAS_POLL_MS);

  await refreshRiskHistory();
  if (riskHistoryPollHandle) clearInterval(riskHistoryPollHandle);
  riskHistoryPollHandle = setInterval(refreshRiskHistory, RISK_HISTORY_POLL_MS);
}

/* ─────────────────────────────────────────────
   Theme -- dark (default/current) or light, plus a couple of optional
   accent-color presets, both persisted client-side (localStorage) so the
   choice survives across sessions/reloads. Applied via a data-theme/
   data-accent attribute on <html> that style.css's token overrides key off
   of -- see the ":root[data-theme=...]"/":root[data-accent=...]" blocks
   there. The actual attribute is also set synchronously by a tiny inline
   script at the top of index.html's <head>, BEFORE this file (which loads
   with `defer`, i.e. after the DOM/CSS would already have painted once) --
   that's what avoids a flash of the wrong theme on load; the functions
   here are what the nav drawer's buttons call to change it afterward.
   ───────────────────────────────────────────── */
const THEME_STORAGE_KEY = 'litds_theme';
const ACCENT_STORAGE_KEY = 'litds_accent';

function applyThemeControlsState() {
  const theme = document.documentElement.getAttribute('data-theme') || 'dark';
  const darkBtn = document.getElementById('themeDarkBtn');
  const lightBtn = document.getElementById('themeLightBtn');
  if (darkBtn) darkBtn.classList.toggle('active', theme === 'dark');
  if (lightBtn) lightBtn.classList.toggle('active', theme === 'light');

  const accent = document.documentElement.getAttribute('data-accent') || 'default';
  document.querySelectorAll('.accent-swatch').forEach(el => {
    el.classList.toggle('active', el.dataset.accent === accent);
  });
}

function setTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  try { localStorage.setItem(THEME_STORAGE_KEY, theme); } catch (e) { /* private browsing, etc. -- theme just won't persist */ }
  applyThemeControlsState();
}

function setAccent(accent) {
  // 'default' is represented by the ABSENCE of data-accent (style.css's
  // plain :root already has the default accent values) rather than its
  // own explicit override block -- one fewer thing to keep in sync with
  // :root if the default ever changes.
  if (accent === 'default') {
    document.documentElement.removeAttribute('data-accent');
  } else {
    document.documentElement.setAttribute('data-accent', accent);
  }
  try { localStorage.setItem(ACCENT_STORAGE_KEY, accent); } catch (e) { /* private browsing, etc. */ }
  applyThemeControlsState();
}

/* ─────────────────────────────────────────────
   Nav drawer (hamburger menu)
   ───────────────────────────────────────────── */
function toggleNav() {
  const open = document.getElementById('navPanel').classList.toggle('open');
  document.getElementById('navBackdrop').classList.toggle('open', open);
}
function closeNav() {
  document.getElementById('navPanel').classList.remove('open');
  document.getElementById('navBackdrop').classList.remove('open');
}

/* ─────────────────────────────────────────────
   Routing — employee profile is a real route (#/employees/{id}), not
   modal state. A hash fragment, not a clean pushState path, and
   deliberately so: GET /employees/{id} already exists as a JSON API route
   on this exact origin (routes/employees.py) -- a clean path here would
   collide with it (a plain browser navigation would hit the API route,
   get a 401/raw JSON, never reach this page). A hash fragment is never
   sent to the server at all, so there's no collision, no server-side
   catch-all route needed, and it's still fully bookmarkable/shareable,
   restores correctly on refresh, and browser back/forward work via the
   native hashchange event.
   ───────────────────────────────────────────── */
function isEmployeeRoute() {
  return location.hash.startsWith('#/employees/');
}
// All Employees -- a real route (#/employees, no trailing slash), same
// treatment as the routes below. Deliberately distinct from
// #/employees/{id} above (which isEmployeeRoute checks via the trailing
// slash) so the two never collide -- "#/employees" alone never matches
// isEmployeeRoute's startsWith('#/employees/') check.
function isAllEmployeesRoute() {
  return location.hash === '#/employees';
}
// Company Profile -- same real-route treatment as the employee profile
// above (was an overlay/popup; converted for consistency, and because a
// bookmarkable/back-button-friendly settings page is just as reasonable
// here as it is for an employee). No dynamic segment, so an exact match
// is enough -- unlike #/employees/{id}, there's nothing to parse out of it.
function isCompanyRoute() {
  return location.hash === '#/company';
}
function deviceIdFromHash() {
  return decodeURIComponent(location.hash.slice('#/employees/'.length));
}
function navigateToEmployee(deviceId) {
  location.hash = '#/employees/' + encodeURIComponent(deviceId);
}
// No navigateToAllEmployees() function -- the panel-title link that reaches
// this route is a plain <a href="#/employees">, same as .stat-dropdown-name
// links straight to #/employees/{id} without going through
// navigateToEmployee(); a JS wrapper is only needed where something else
// (closeNav(), an id lookup) has to run alongside the hash change.
function navigateToCompany() {
  location.hash = '#/company';
}
function navigateHome() {
  if (location.hash === '#/' || location.hash === '') {
    showDashboardPage();
  } else {
    location.hash = '#/';
  }
}
async function showDashboardPage() {
  document.getElementById('profileView').classList.add('hidden');
  document.getElementById('companyView').classList.add('hidden');
  document.getElementById('allEmployeesView').classList.add('hidden');
  document.getElementById('dashboardView').classList.remove('hidden');
}
async function showProfilePage(deviceId) {
  document.getElementById('dashboardView').classList.add('hidden');
  document.getElementById('companyView').classList.add('hidden');
  document.getElementById('allEmployeesView').classList.add('hidden');
  document.getElementById('profileView').classList.remove('hidden');
  renderedHistorySignature = null; // force a fresh render when switching to a different profile
  await renderProfileData(deviceId);
}
// All Employees -- reuses renderEmployeeGrid() (which already renders into
// both this page's #allEmployeesGrid and the dashboard's #employeeGrid,
// see that function's own comment) rather than any new rendering code.
// Called once immediately on entering this route so the list appears
// right away instead of waiting for refreshAll's next 5s poll.
async function showAllEmployeesPage() {
  document.getElementById('dashboardView').classList.add('hidden');
  document.getElementById('profileView').classList.add('hidden');
  document.getElementById('companyView').classList.add('hidden');
  document.getElementById('allEmployeesView').classList.remove('hidden');
  renderEmployeeGrid();
}
async function showCompanyPage() {
  document.getElementById('dashboardView').classList.add('hidden');
  document.getElementById('profileView').classList.add('hidden');
  document.getElementById('allEmployeesView').classList.add('hidden');
  document.getElementById('companyView').classList.remove('hidden');
  // Loaded fresh every time this route is entered, same as the employee
  // profile's renderProfileData -- NOT polled every 5s by refreshAll like
  // the dashboard grid, deliberately: this view is mostly configuration
  // an admin edits directly (SMTP fields, department forms), and a
  // periodic innerHTML rebuild here risks clobbering mid-typed input the
  // same way an unguarded rebuild would for renderPending/the edit-
  // employee form -- see loadCompanyPage's own comment.
  await loadCompanyPage();
}
async function routeFromHash() {
  if (!token) return; // not logged in yet -- nothing to route to
  if (isEmployeeRoute()) {
    const id = deviceIdFromHash();
    if (id) { await showProfilePage(id); } else { navigateHome(); }
  } else if (isAllEmployeesRoute()) {
    await showAllEmployeesPage();
  } else if (isCompanyRoute()) {
    await showCompanyPage();
  } else {
    await showDashboardPage();
  }
}
window.addEventListener('hashchange', routeFromHash);

/* ─────────────────────────────────────────────
   Data refresh
   ───────────────────────────────────────────── */
let devices = [];
let employees = [];
let alerts = [];
let employeeDetailCache = {};
let company = null;
let archivedEmployees = [];
let me = null; // the logged-in admin's own profile, from GET /admin/me

// Was a hardcoded const matching core/config.py's old fixed department
// list -- departments are now a per-company, admin-managed set (GET
// /company/departments), fetched fresh in refreshAll() below like every
// other piece of company data. `departments` holds EVERY department this
// company has (active or soft-removed, same shape the admin-management
// list on the Company Profile page needs); `activeDepartments()` is what
// the pending-device approval row and the edit-employee form actually
// offer as selectable options -- a removed department stays visible on
// the management list but stops being an option for a NEW assignment.
let departments = [];
function activeDepartments() {
  return departments.filter(d => d.is_active);
}
// Display-only capitalization for a department's raw stored name (kept
// exactly as the admin typed it in the value/comparison -- this never
// touches what's actually stored or submitted, purely how it reads in a
// dropdown/list).
function departmentLabel(name) {
  return (name || '').replace(/\b\w/g, c => c.toUpperCase());
}
function departmentOptionsHtml(selected) {
  return activeDepartments()
    .map(d => `<option value="${d.name}" ${d.name === selected ? 'selected' : ''}>${departmentLabel(d.name)}</option>`)
    .join('');
}

function levelClass(level) {
  level = (level || '').toLowerCase();
  if (['low', 'medium', 'high', 'critical'].includes(level)) return level;
  return 'low';
}
// Every timestamp shown to an admin renders in Mauritius time (Indian/
// Mauritius, UTC+4, no DST -- a fixed offset year-round, which is exactly
// what makes the built-in IANA zone identifier a correct choice here: no
// daylight-saving transition dates to get wrong by hand-rolling a "+4
// hours" offset). This is DISPLAY ONLY -- nothing about how timestamps
// are stored, compared, or fed into decay/dedup/streak math changes; the
// backend still stores and reasons in UTC exactly as before. Labelled
// "MUT" so an admin viewing this from a different timezone doesn't
// mistake it for their own local time.
//
// Depends on the backend actually sending an unambiguous UTC string
// (core/db.py's UTCDateTime) -- confirmed live before this was written
// that the API used to omit the timezone offset entirely (SQLite's
// round-trip losing it), which would have made this conversion silently
// wrong: `new Date(...)` treats an offset-less ISO string as LOCAL
// browser time, not UTC, so converting an already-mis-parsed value to
// "Mauritius time" would have compounded the error rather than fixed it.
function timestamp(iso) {
  try {
    return new Date(iso).toLocaleString('en-GB', {
      timeZone: 'Indian/Mauritius',
      year: 'numeric', month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
    }) + ' MUT';
  } catch (e) {
    return iso || '';
  }
}

async function refreshAll() {
  try {
    const [companyRes, deviceRes, employeeRes, alertRes, archivedRes, meRes, departmentsRes] = await Promise.all([
      authFetch('/company/me'),
      authFetch('/device'),
      authFetch('/employees'),
      authFetch('/alerts'),
      authFetch('/employees?status_filter=offboarded'),
      authFetch('/admin/me'),
      authFetch('/company/departments'),
    ]);
    company = await companyRes.json();
    devices = await deviceRes.json();
    employees = await employeeRes.json();
    alerts = await alertRes.json();
    archivedEmployees = await archivedRes.json();
    me = await meRes.json();
    departments = await departmentsRes.json();

    document.getElementById('companyNameLabel').innerText = company.company_name;
    document.getElementById('companyCodeBox').innerText = company.company_code;
    document.getElementById('navCompanyName').innerText = company.company_name;
    document.getElementById('navAdminName').innerText = me.username;
    document.getElementById('navArchivedCount').innerText = archivedEmployees.length;
    // Owner-only nav entry -- hidden client-side for every other role
    // (routes/admin.py's require_owner is the real gate; this is just
    // not showing a door to an action that would 403).
    document.getElementById('navAdminAccountsLink').classList.toggle('hidden', me.role !== 'owner');

    render();

    // The grid/alerts/pending panel above are the only things render()
    // touches -- an already-open employee profile was otherwise a static
    // snapshot from the moment it was clicked, never reflecting new log
    // activity, risk changes, or AI Reasoning Core judgments that arrived
    // while it stayed open. isBackgroundRefresh=true skips rebuilding the
    // Edit Employee form and the reasoning panel's override dropdowns so
    // this doesn't clobber anything the admin has mid-typed/mid-selected.
    if (isEmployeeRoute()) {
      await renderProfileData(deviceIdFromHash(), true);
    }
    // Raw logs overlay had NO polling at all before this -- confirmed as
    // the actual cause of "logs aren't appearing in real time" (see the
    // comment on rawLogsOverlayOpen's declaration). Reloads whatever page
    // is currently being viewed, so new rows show up without needing to
    // close/reopen -- on page 1 (offset 0, newest-first) that means new
    // logs simply appear at the top on the next poll.
    if (rawLogsOverlayOpen) {
      await loadRawLogsPage(true);
    }
  } catch (e) {
    if (e.message !== 'unauthorized') console.error('refresh failed', e);
  }
}

// Risk is no longer computed client-side at all -- GET /employees and
// GET /employees/{id} both return risk_score/risk_level straight off
// Device.current_risk_score (a persisted, continuously-decaying value
// agent_logic/analyzer.py maintains server-side; see docs/known_
// limitations.md's risk-scoring-redesign entry). Grid, top-risk list, and
// profile all just read emp.risk_score / emp.risk_level directly now --
// there used to be a client-side currentRiskFor() scanning the alerts
// array here, which is exactly what let the grid and the profile page
// disagree in the first place (two independent calculations of the same
// thing). One number, computed once, server-side.

/* ─────────────────────────────────────────────
   Render (dashboard view)
   ───────────────────────────────────────────── */
function render() {
  const pending = devices.filter(d => d.approval_status === 'pending');
  const hasAnyDevice = devices.length > 0;

  document.getElementById('emptyState').classList.toggle('hidden', hasAnyDevice);
  document.getElementById('pendingPanel').classList.toggle('hidden', pending.length === 0);
  document.getElementById('mainLayout').classList.toggle('hidden', employees.length === 0);
  // Same visibility condition as mainLayout -- charts/health strip don't
  // mean anything yet on a company with zero employees.
  document.getElementById('overviewExtras').classList.toggle('hidden', employees.length === 0);

  renderPending(pending);
  renderStats();
  renderEmployeeGrid();
  renderTopRisks();
  renderAlertFeed();
  renderRiskDonut(); // client-computed from the same `employees` this render() call already has fresh
}

// A previous pass anchored .layout's height to a JS measurement of "4
// employee cards visible" (computeLiveMonitoringAnchorHeight/
// applyLayoutHeightAnchor, called from here). That's gone now that Live
// Employee Monitoring is a compact row-list rather than large cards --
// see style.css's .layout/.overview-extras comments: the space split is
// pure CSS flex now (.layout flex:1, .overview-extras flex:none), no JS
// measurement needed at all.

let renderedPendingIds = null;

function renderPending(pending) {
  // Rebuilding this panel's innerHTML on every 5s poll destroyed and
  // recreated the <input> elements each time, which wiped whatever the
  // admin had half-typed and stole focus out from under them — even a
  // single keystroke would get "ejected." Only rebuild when the actual
  // set of pending devices has changed; while it's the same devices, leave
  // the DOM (and whatever's mid-typing in it) alone.
  const ids = pending.map(d => d.device_id).sort().join(',');
  if (ids === renderedPendingIds) return;
  renderedPendingIds = ids;

  const list = document.getElementById('pendingList');
  list.innerHTML = '';
  pending.forEach(d => {
    const row = document.createElement('div');
    row.className = 'pending-row';
    row.innerHTML = `
      <div class="pending-info">
        <div class="pending-hostname">${d.hostname}</div>
        <div class="pending-meta">${d.username || 'unknown user'} · ${d.ip_address || 'no IP'}</div>
      </div>
      <input type="text" placeholder="Employee name" id="label-${d.device_id}" value="${d.username || d.hostname || ''}" />
      <select id="dept-${d.device_id}">
        <option value="">Department…</option>
        ${departmentOptionsHtml(null)}
      </select>
      <input type="email" placeholder="Email (optional)" id="email-${d.device_id}" />
      <button class="approve-btn" onclick="approveDevice('${d.device_id}')">Approve</button>
      <button class="profile-header-btn danger" onclick="rejectDevice('${d.device_id}')">Reject</button>
    `;
    list.appendChild(row);
  });
}

async function approveDevice(deviceId) {
  const label = document.getElementById(`label-${deviceId}`).value.trim();
  const department = document.getElementById(`dept-${deviceId}`).value;
  const email = document.getElementById(`email-${deviceId}`).value.trim();
  if (!label) { alert('Enter the employee name first'); return; }
  await authFetch(`/device/${deviceId}/approve`, {
    method: 'POST',
    body: JSON.stringify({ label, department: department || null, email: email || null }),
  });
  await refreshAll();
}

async function rejectDevice(deviceId) {
  if (!confirm('Reject this enrollment request? The device can attempt to enroll again later if needed.')) return;
  const res = await authFetch(`/device/${deviceId}/reject`, { method: 'POST' });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    alert(err.detail || 'Could not reject this device.');
    return;
  }
  await refreshAll();
}

function renderStats() {
  const onlineEmployees = statDropdownEmployees('online');
  document.getElementById('onlineRatioValue').innerText = `${onlineEmployees.length}/${employees.length} Online`;
  document.getElementById('criticalCount').innerText = statDropdownEmployees('critical').length;
  document.getElementById('openAlertCount').innerText = statDropdownEmployees('openAlerts').length;

  // Keep an already-open dropdown's contents live across refreshAll's 5s
  // poll, same as every other panel on this page, instead of freezing
  // whatever was rendered at the moment it was opened.
  if (openStatDropdown) renderStatDropdownList(openStatDropdown);
}

/* ─────────────────────────────────────────────
   Top bar KPI dropdowns -- Online/Critical/Open Alerts pills are buttons;
   clicking one lists the relevant employees (name/department/score only,
   name links to their profile). Built entirely from data already loaded
   for the main dashboard panels (employees + devices) -- GET /employees
   already returns risk_level/risk_score/department/open_alert_count per
   employee, and GET /device already returns connection_status per device
   (the exact fields the removed per-card badge and the row/card renderers
   already read) -- so no new endpoint was needed for this.
   ───────────────────────────────────────────── */
let openStatDropdown = null; // null | 'online' | 'critical' | 'openAlerts'

function statDropdownEmployees(which) {
  if (which === 'online') {
    return employees.filter(emp => {
      const device = devices.find(d => d.device_id === deviceIdFor(emp));
      return device && device.connection_status === 'online';
    });
  }
  if (which === 'critical') {
    return employees.filter(emp => levelClass(emp.risk_level) === 'critical');
  }
  if (which === 'openAlerts') {
    return employees.filter(emp => emp.open_alert_count > 0);
  }
  return [];
}

function renderStatDropdownList(which) {
  const el = document.getElementById(`${which}StatDropdown`);
  if (!el) return;
  const list = statDropdownEmployees(which).slice().sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0));
  if (list.length === 0) {
    el.innerHTML = `<div class="stat-dropdown-empty">None right now.</div>`;
    return;
  }
  el.innerHTML = list.map(emp => `
    <div class="stat-dropdown-row">
      <a href="#/employees/${encodeURIComponent(deviceIdFor(emp))}" class="stat-dropdown-name" onclick="closeStatDropdown()">${emp.label || emp.hostname}</a>
      <span class="stat-dropdown-dept">${emp.department || 'no department set'}</span>
      <span class="stat-dropdown-score ${levelClass(emp.risk_level)}">${Math.round(emp.risk_score || 0)}</span>
    </div>
  `).join('');
}

function toggleStatDropdown(which) {
  if (openStatDropdown === which) {
    closeStatDropdown();
    return;
  }
  openStatDropdown = which;
  ['online', 'critical', 'openAlerts'].forEach(w => {
    const el = document.getElementById(`${w}StatDropdown`);
    const btn = document.getElementById(`${w}StatBtn`);
    if (!el || !btn) return;
    const isOpen = w === which;
    el.classList.toggle('hidden', !isOpen);
    btn.classList.toggle('active', isOpen);
    if (isOpen) renderStatDropdownList(w);
  });
}

function closeStatDropdown() {
  openStatDropdown = null;
  ['online', 'critical', 'openAlerts'].forEach(w => {
    const el = document.getElementById(`${w}StatDropdown`);
    const btn = document.getElementById(`${w}StatBtn`);
    if (el) el.classList.add('hidden');
    if (btn) btn.classList.remove('active');
  });
}

// Click-outside-to-close, same pattern as the nav drawer's backdrop but
// without needing a dedicated full-screen backdrop element for a small
// dropdown -- any click that didn't land inside a .stat-pill-dropdown
// closes whichever one is open.
document.addEventListener('click', (e) => {
  if (!openStatDropdown) return;
  if (!e.target.closest('.stat-pill-dropdown')) closeStatDropdown();
});

/* ─────────────────────────────────────────────
   Risk-score sparkline -- 24h trend per Live Employee Monitoring card
   (backend/models/risk_snapshot.py's DeviceRiskSnapshot, populated every
   ~15 minutes by the scheduler; GET /employees/risk-history bulk-fetches
   all of them in one request). Experimental per the request that added
   it -- deliberately self-contained (its own poll, its own render step,
   no changes to any other card field) so it can be pulled back out
   cleanly without touching anything else if it turns out too busy once
   actually seen.

   sparklinePoints() is kept as a pure function (input data in, an SVG
   points string out, no DOM) specifically so it can be exercised outside
   a full browser -- this is exactly what was used to verify the sparkline
   draws a correctly-shaped trend against real recorded score movement,
   not just that snapshot rows exist.
   ───────────────────────────────────────────── */
let riskHistory = {}; // device_public_id -> [{recorded_at, risk_score}, ...], chronological
const RISK_HISTORY_POLL_MS = 60000; // 15-minute-granularity data gets nothing from 5s refresh

// Maps a chronological [{recorded_at, risk_score}, ...] list onto an SVG
// polyline's "x,y x,y ..." points string within a width x height box, or
// null if there's nothing to draw a trend from (fewer than 2 points).
// x is spaced evenly BY INDEX, not by real elapsed time -- at this size a
// sparkline is a shape/trend indicator, not a precisely time-scaled
// chart, and even spacing reads more cleanly across a gap (e.g. a device
// briefly offline) than time-proportional spacing would. y is inverted
// (SVG y grows downward) so a HIGHER risk score draws HIGHER on the
// sparkline, matching how risk reads everywhere else in this app --
// bigger number, more visually prominent, never the reverse.
function sparklinePoints(history, width, height) {
  if (!history || history.length < 2) return null;
  const scores = history.map(h => h.risk_score);
  const min = Math.min(...scores);
  const max = Math.max(...scores);
  const range = max - min || 1; // flat history (every value equal) -- avoid divide-by-zero; draws a flat centered line
  const stepX = width / (history.length - 1);
  return history
    .map((h, i) => {
      const x = i * stepX;
      const y = height - ((h.risk_score - min) / range) * height;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(' ');
}

function renderSparklineSvg(history) {
  const width = 100, height = 26;
  const points = sparklinePoints(history, width, height);
  if (!points) return ''; // fewer than 2 snapshots yet -- nothing to draw, card just omits the sparkline entirely
  // Neutral line color (--text-faint), NOT severity-colored -- keeps this
  // app's rule that color encodes severity specifically (and only the
  // four low/medium/high/critical bands) intact; this is a shape/trend
  // indicator riding alongside the score, not a second severity signal.
  return `
    <svg class="card-sparkline-svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" preserveAspectRatio="none">
      <polyline points="${points}" fill="none" stroke="var(--text-faint)" stroke-width="1.5" stroke-linejoin="round" stroke-linecap="round" />
    </svg>
  `;
}

async function refreshRiskHistory() {
  // Separate from refreshAll's 5s poll on purpose: snapshots are only
  // ever taken every ~15 minutes (core/config.py's RISK_SNAPSHOT_
  // INTERVAL_MINUTES) -- refetching this every 5s would just be the exact
  // same response over and over almost every time.
  try {
    const res = await authFetch('/employees/risk-history');
    riskHistory = await res.json();
  } catch (e) {
    if (e.message !== 'unauthorized') console.error('risk history refresh failed', e);
  }
}

function buildEmployeeRowData(emp) {
  // Shared per-employee data prep for both the list (row) and grid (card)
  // render paths below -- keeps the level/score/online/sparkline
  // computation in exactly one place rather than duplicated across two
  // markup builders. The open-alerts badge that used to live here too was
  // removed -- that count now surfaces via the top bar's "Open Alerts"
  // dropdown instead (see statDropdownEmployees), not on individual
  // cards/rows.
  const deviceId = deviceIdFor(emp);
  const level = emp.risk_level || 'low';
  const score = Math.round(emp.risk_score || 0);
  const device = devices.find(d => d.device_id === deviceId);
  const online = device && device.connection_status === 'online';

  // Experimental 24h trend sparkline -- see this section's own header
  // comment. Reads whatever refreshRiskHistory's own (slower, ~60s) poll
  // currently has cached; this function itself still runs every 5s same
  // as always, it just isn't what's fetching this data. Renders nothing
  // (not an empty box) for a device with fewer than 2 snapshots yet --
  // e.g. one just approved in the last 15 minutes.
  const sparkline = renderSparklineSvg(riskHistory[deviceId]);

  return { deviceId, level, score, online, sparkline };
}

function renderEmployeeRow(emp, data) {
  const { deviceId, level, score, online, sparkline } = data;
  const sparklineHtml = sparkline ? `<div class="employee-row-spark">${sparkline}</div>` : '';
  const row = document.createElement('div');
  row.className = `employee-row sev-${levelClass(level)}`;
  row.onclick = () => navigateToEmployee(deviceId);
  row.innerHTML = `
    <div class="live-dot ${online ? 'online' : 'offline'}" title="${online ? 'Online' : 'Offline'}" aria-label="${online ? 'Online' : 'Offline'}"></div>
    <div class="employee-row-identity">
      <div class="employee-row-name">${emp.label || emp.hostname}</div>
      <div class="employee-row-dept">${emp.department || 'no department set'}</div>
    </div>
    ${sparklineHtml}
    <div class="employee-row-score">
      <div class="employee-row-score-num ${levelClass(level)}">${score}</div>
      <div class="employee-row-score-label ${levelClass(level)}">${level} risk</div>
    </div>
  `;
  return row;
}

function renderEmployeeCard(emp, data) {
  const { deviceId, level, score, online, sparkline } = data;
  const sparklineHtml = sparkline ? `<div class="employee-card-spark">${sparkline}</div>` : '';
  const card = document.createElement('div');
  card.className = `employee-card sev-${levelClass(level)}`;
  card.onclick = () => navigateToEmployee(deviceId);
  card.innerHTML = `
    <div class="employee-card-top">
      <div class="live-dot ${online ? 'online' : 'offline'}" title="${online ? 'Online' : 'Offline'}" aria-label="${online ? 'Online' : 'Offline'}"></div>
    </div>
    <div class="employee-card-name">${emp.label || emp.hostname}</div>
    <div class="employee-card-dept">${emp.department || 'no department set'}</div>
    ${sparklineHtml}
    <div class="employee-card-bottom">
      <div class="employee-card-score-num ${levelClass(level)}">${score}</div>
      <div class="employee-card-score-label">${level} risk</div>
    </div>
  `;
  return card;
}

// Both the dashboard's own box (#employeeGrid) and the dedicated full page
// (#allEmployeesGrid, #/employees -- see showAllEmployeesPage) show the
// exact same employee list/grid, driven by the same shared
// employeeViewMode/employeeGridCols state -- so both containers are kept
// in sync here rather than the full page duplicating this rendering.
// #allEmployeesGrid doesn't exist until the DOM's loaded, hence the null
// checks; it's always in the DOM once the app boots (just hidden when
// that route isn't active), so this always keeps it current, not just
// while the page happens to be visible.
const EMPLOYEE_GRID_CONTAINER_IDS = ['employeeGrid', 'allEmployeesGrid'];

function renderEmployeeGrid() {
  // Dispatches between List mode (.employee-list/.employee-row, the
  // default -- what the previous round's "replace the 2x2 grid" request
  // landed on) and Grid mode (.employee-cards-grid/.employee-card, a
  // reintroduced card component with an adjustable column count) based on
  // employeeViewMode, set via the view-toggle in this panel's header (and
  // the identical toggle on the full-page view) and persisted in
  // localStorage same as the theme toggle. Name kept for continuity with
  // refreshAll()/render()'s existing call site.
  const sorted = employees.slice().sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0));
  EMPLOYEE_GRID_CONTAINER_IDS.forEach(containerId => {
    const grid = document.getElementById(containerId);
    if (!grid) return;
    grid.className = employeeViewMode === 'grid' ? 'employee-cards-grid' : 'employee-list';
    if (employeeViewMode === 'grid') {
      grid.style.setProperty('--employee-grid-cols', employeeGridCols);
    } else {
      grid.style.removeProperty('--employee-grid-cols');
    }
    grid.innerHTML = '';
    sorted.forEach(emp => {
      const data = buildEmployeeRowData(emp);
      const el = employeeViewMode === 'grid' ? renderEmployeeCard(emp, data) : renderEmployeeRow(emp, data);
      grid.appendChild(el);
    });
  });
}

/* ─────────────────────────────────────────────
   Live Employee Monitoring view mode (list/grid) -- same persisted-choice
   pattern as the theme toggle above (localStorage + an "apply saved state
   to the controls" function called once at boot).
   ───────────────────────────────────────────── */
const EMPLOYEE_VIEW_MODE_KEY = 'litds_employee_view_mode';
const EMPLOYEE_GRID_COLS_KEY = 'litds_employee_grid_cols';
let employeeViewMode = 'list';
let employeeGridCols = '2';
try { employeeViewMode = localStorage.getItem(EMPLOYEE_VIEW_MODE_KEY) || 'list'; } catch (e) { /* private browsing, etc. */ }
try { employeeGridCols = localStorage.getItem(EMPLOYEE_GRID_COLS_KEY) || '2'; } catch (e) { /* private browsing, etc. */ }

// One shared view-mode/column-count choice, reflected onto BOTH sets of
// controls -- the dashboard box's header and the full page's header --
// since they drive the exact same state (see renderEmployeeGrid's own
// comment). Toggling either one updates both, same as a single source of
// truth should.
const EMPLOYEE_VIEW_CONTROL_IDS = [
  { list: 'employeeViewListBtn', grid: 'employeeViewGridBtn', select: 'employeeGridColsSelect' },
  { list: 'allEmployeesViewListBtn', grid: 'allEmployeesViewGridBtn', select: 'allEmployeesGridColsSelect' },
];

function updateEmployeeViewControls() {
  EMPLOYEE_VIEW_CONTROL_IDS.forEach(ids => {
    const listBtn = document.getElementById(ids.list);
    const gridBtn = document.getElementById(ids.grid);
    const colsSelect = document.getElementById(ids.select);
    if (listBtn) listBtn.classList.toggle('active', employeeViewMode === 'list');
    if (gridBtn) gridBtn.classList.toggle('active', employeeViewMode === 'grid');
    if (colsSelect) {
      colsSelect.classList.toggle('hidden', employeeViewMode !== 'grid');
      colsSelect.value = employeeGridCols;
    }
  });
}

function setEmployeeViewMode(mode) {
  employeeViewMode = mode;
  try { localStorage.setItem(EMPLOYEE_VIEW_MODE_KEY, mode); } catch (e) { /* private browsing, etc. -- choice just won't persist */ }
  updateEmployeeViewControls();
  renderEmployeeGrid();
}

function setEmployeeGridColumns(cols) {
  employeeGridCols = cols;
  try { localStorage.setItem(EMPLOYEE_GRID_COLS_KEY, cols); } catch (e) { /* private browsing, etc. */ }
  updateEmployeeViewControls();
  renderEmployeeGrid();
}

function deviceIdFor(emp) {
  // /employees returns device_id as the public_id string — kept as its own
  // helper in case that response shape changes later.
  return emp.device_id;
}

function renderTopRisks() {
  // Despite the panel's old "Top Risk Employees" name, this used to
  // .slice(0, 5) — a silent top-5 truncation, not the full roster the name
  // implied. Renamed (index.html's panel-title) to match what it actually
  // shows now: every employee, sorted highest-risk first, with no cap —
  // .panel-content already has its own independent overflow-y:auto (see
  // style.css's MAIN LAYOUT section), so a long roster scrolls within this
  // one panel instead of needing a truncated preview.
  const riskList = document.getElementById('riskList');
  riskList.innerHTML = '';
  employees
    .slice()
    .sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0))
    .forEach(emp => {
      const level = emp.risk_level || 'low';
      const score = Math.round(emp.risk_score || 0);
      const item = document.createElement('div');
      item.className = `risk-item sev-${levelClass(level)}`;
      item.innerHTML = `
        <div class="risk-top">
          <div>
            <div class="risk-user">${emp.label || emp.hostname}</div>
            <div class="risk-dept">${emp.department || ''}</div>
          </div>
          <div class="risk-score ${levelClass(level)}">${score}</div>
        </div>
      `;
      riskList.appendChild(item);
    });
}

function renderAlertFeed() {
  const feed = document.getElementById('aiFeed');
  feed.innerHTML = '';
  const recent = alerts.slice().sort((a, b) => new Date(b.created_at) - new Date(a.created_at)).slice(0, 20);
  if (!recent.length) {
    feed.innerHTML = '<div class="ai-empty">No alerts yet — quiet so far.</div>';
    return;
  }
  recent.forEach(a => {
    const emp = employees.find(e => deviceIdFor(e) === a.device_id);
    const box = document.createElement('div');
    box.className = `ai-box sev-${levelClass(a.risk_level)}`;
    box.innerHTML = `
      <div class="ai-user">${emp ? (emp.label || emp.hostname) : 'device ' + a.device_id.slice(0, 8)}</div>
      <div class="ai-section">
        <div class="ai-section-title">THREAT ASSESSMENT</div>
        <div class="${levelClass(a.risk_level)} mono">${a.risk_level} (${a.risk_score}/100)</div>
      </div>
      <div class="ai-section">
        <div class="ai-section-title">ANOMALY</div>
        <div class="ai-anomaly">${a.title}</div>
      </div>
      <div class="ai-section">
        <div class="ai-section-title">REASONING</div>
        <div>${a.description || ''}</div>
      </div>
      <div class="ai-section">
        <div class="ai-section-title">STATUS</div>
        <div class="mono">${a.status} · ${timestamp(a.created_at)}</div>
      </div>
    `;
    feed.appendChild(box);
  });
}

/* ─────────────────────────────────────────────
   Overview extras -- Risk Distribution donut (client-computed, from the
   same `employees` refreshAll's 5s poll already loads -- no extra
   request), plus the two 7-day trend bar charts and the system-health
   strip (both server-aggregated, polled on their own longer cadence, see
   refreshOverviewExtras below). No charting library anywhere -- confirmed
   none exists in this dashboard before adding these; introducing one now
   (vendored or CDN) would be a new dependency this project's whole
   "no build step, works with nothing but Python 3.10+ installed" story
   was built to avoid (see style.css's own comment on .bar-chart). Plain
   inline SVG for the donut (a real ring genuinely needs arc geometry);
   plain CSS bars (flex column heights) for the two trend charts.
   ───────────────────────────────────────────── */
const SEVERITY_COLOR_VAR = { low: 'var(--low)', medium: 'var(--medium)', high: 'var(--high)', critical: 'var(--critical)' };
const OVERVIEW_EXTRAS_POLL_MS = 20000; // slower than refreshAll's 5s -- see this section's header comment

function renderRiskDonut() {
  const el = document.getElementById('riskDonutChart');
  if (!el) return; // not on this page (shouldn't happen, but this fn is called from every render())
  const counts = { low: 0, medium: 0, high: 0, critical: 0 };
  employees.forEach(e => {
    const lvl = levelClass(e.risk_level);
    counts[lvl] = (counts[lvl] || 0) + 1;
  });
  const total = employees.length;
  if (!total) {
    el.innerHTML = '<div class="ai-empty">No employees yet.</div>';
    return;
  }

  // Classic SVG donut: one <circle> per band, stroke-dasharray covering
  // exactly its share of the circumference, stroke-dashoffset advancing
  // each segment's start point around the ring. Drawn critical-first (most
  // severe most visually prominent at the top, since rotate(-90) starts
  // every circle at 12 o'clock) though visual order doesn't affect the
  // math -- each segment's own offset is independent of draw order.
  // Sized to 96x96 (was 140x140) as part of fitting the whole Overview
  // page in one viewport -- style.css's .chart-panel-body/.bar-chart were
  // both compacted to match; see that file's own comment on the height
  // budget this is sized against.
  const size = 96, center = size / 2, radius = 34, strokeWidth = 12, circumference = 2 * Math.PI * radius;
  const order = ['critical', 'high', 'medium', 'low'];
  let offset = 0;
  const segments = order.map(level => {
    const count = counts[level] || 0;
    if (!count) return '';
    const dash = (count / total) * circumference;
    const circle = `<circle cx="${center}" cy="${center}" r="${radius}" fill="none" stroke="${SEVERITY_COLOR_VAR[level]}" stroke-width="${strokeWidth}" stroke-dasharray="${dash} ${circumference - dash}" stroke-dashoffset="${-offset}" transform="rotate(-90 ${center} ${center})" />`;
    offset += dash;
    return circle;
  }).join('');

  const legend = order.map(level => `
    <div class="donut-legend-row">
      <span class="donut-legend-dot" style="background:${SEVERITY_COLOR_VAR[level]}"></span>
      <span>${level} — ${counts[level] || 0}</span>
    </div>
  `).join('');

  el.innerHTML = `
    <div style="display:flex;align-items:center;gap:16px;flex-wrap:wrap;">
      <svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" style="flex:none;">
        ${segments}
        <text x="${center}" y="${center + 5}" text-anchor="middle" fill="var(--text)" font-size="15" font-weight="700" font-family="var(--mono)">${total}</text>
      </svg>
      <div>${legend}</div>
    </div>
  `;
}

// Smooth curve through every point -- monotone cubic Hermite interpolation
// (Fritsch-Carlson), NOT Catmull-Rom (was Catmull-Rom; switched after a
// real overshoot bug was reported: two adjacent high values near the axis
// max made the curve bulge past the top gridline, because Catmull-Rom's
// tangents are derived purely from neighbor positions with no constraint
// keeping a segment within its own two endpoints' value range). Monotone
// cubic fixes this at the source rather than papering over it with a
// clamp: for every segment, the tangents at both ends are clamped
// (Fritsch-Carlson's sign + magnitude condition below) so the curve is
// mathematically guaranteed to never exceed max(p0.y, p1.y) or drop below
// min(p0.y, p1.y) within that segment -- a local peak gets a zero tangent
// rather than being overshot from either side. By construction the curve
// still passes exactly through every input point (a Hermite spline
// always interpolates its knots) -- this stays a faithful trend line
// tracing the actual data, not an approximation, same as the Catmull-Rom
// version was, just without its overshoot failure mode. Pure function (no
// DOM) so it can be exercised outside a browser the same way
// sparklinePoints() already is.
function monotoneCubicPath(points) {
  const n = points.length;
  if (n === 0) return '';
  if (n === 1) return `M ${points[0].x.toFixed(2)},${points[0].y.toFixed(2)}`;
  if (n === 2) {
    return `M ${points[0].x.toFixed(2)},${points[0].y.toFixed(2)} L ${points[1].x.toFixed(2)},${points[1].y.toFixed(2)}`;
  }

  // Secant slope of each segment.
  const dx = [], slope = [];
  for (let i = 0; i < n - 1; i++) {
    const d = points[i + 1].x - points[i].x;
    dx.push(d);
    slope.push(d === 0 ? 0 : (points[i + 1].y - points[i].y) / d);
  }

  // Initial tangent at each point: the endpoints just take their one
  // neighboring segment's slope; interior points start at the average of
  // their two adjacent segments' slopes, EXCEPT a local min/max (the two
  // adjacent slopes have opposite sign, or either is exactly flat) gets a
  // zero tangent immediately -- this is what stops the curve from being
  // pulled past a peak/trough by its neighbor on the other side.
  const m = new Array(n);
  m[0] = slope[0];
  m[n - 1] = slope[n - 2];
  for (let i = 1; i < n - 1; i++) {
    m[i] = (slope[i - 1] <= 0) === (slope[i] <= 0) && slope[i - 1] !== 0 && slope[i] !== 0
      ? (slope[i - 1] + slope[i]) / 2
      : 0;
  }

  // Fritsch-Carlson clamp -- the actual monotonicity guarantee. For each
  // segment, if either endpoint's tangent points the "wrong" way relative
  // to that segment's own slope, zero it; if both tangents are too large
  // relative to the slope (alpha^2+beta^2 > 9), scale them down together.
  // This is a sufficient condition for the cubic on that segment to stay
  // between its own two endpoint values -- no overshoot, by construction.
  for (let i = 0; i < n - 1; i++) {
    if (slope[i] === 0) {
      m[i] = 0;
      m[i + 1] = 0;
      continue;
    }
    const alpha = m[i] / slope[i];
    const beta = m[i + 1] / slope[i];
    if (alpha < 0) m[i] = 0;
    if (beta < 0) m[i + 1] = 0;
    const s = alpha * alpha + beta * beta;
    if (s > 9) {
      const tau = 3 / Math.sqrt(s);
      m[i] = tau * alpha * slope[i];
      m[i + 1] = tau * beta * slope[i];
    }
  }

  let d = `M ${points[0].x.toFixed(2)},${points[0].y.toFixed(2)}`;
  for (let i = 0; i < n - 1; i++) {
    const p0 = points[i], p1 = points[i + 1];
    const h = dx[i];
    const cp1x = p0.x + h / 3;
    const cp1y = p0.y + (m[i] * h) / 3;
    const cp2x = p1.x - h / 3;
    const cp2y = p1.y - (m[i + 1] * h) / 3;
    d += ` C ${cp1x.toFixed(2)},${cp1y.toFixed(2)} ${cp2x.toFixed(2)},${cp2y.toFixed(2)} ${p1.x.toFixed(2)},${p1.y.toFixed(2)}`;
  }
  return d;
}

// Alerts Over Time -- max daily Alert.risk_score (severity), not a raw
// count (see backend/routes/alerts.py's alerts_per_day for the full
// reasoning: a count-based chart always peaks near the top of its own
// range on whichever day had the most alerts, regardless of how trivial
// they were). data: [{label, value, count}] in chronological order,
// value is 0-100. The y-axis is a FIXED 0-100 scale, deliberately NOT
// auto-scaled to this week's own max -- auto-scaling would reintroduce a
// milder version of the same problem (a week whose worst day was 40
// would still show a peak at the very top of the chart). `count` isn't
// dropped -- it surfaces as secondary context in each point's hover
// tooltip ("Max severity: 82 -- 3 alerts that day") rather than driving
// the line.
//
// Still plain inline SVG, no charting library, same as every other chart
// in this app (sparkline/donut/bar) -- reconsidered specifically for this
// round given the added complexity (curve, gradient, dots, gridlines,
// tooltip), not just carried over by default: the curve is one small pure
// function (monotoneCubicPath, tested above), the gradient/gridlines/dots
// are native SVG features with no extra logic, and the tooltip is the same
// kind of plain mouseenter/mousemove/mouseleave handling this file already
// uses elsewhere (the top bar's stat dropdowns). None of that meaningfully
// gets simpler with a library, and a new dependency would cut against this
// project's consistent no-build-step/no-new-install-time-dependency
// packaging story for what's still fundamentally one small chart.
function renderAreaChart(containerId, data, emptyMessage) {
  const el = document.getElementById(containerId);
  if (!el) return;
  if (!data.length || !data.some(d => d.count > 0)) {
    el.innerHTML = `<div class="ai-empty">${emptyMessage}</div>`;
    return;
  }
  // pad -- monotoneCubicPath already guarantees the curve itself never
  // exceeds the value range of its own two neighboring points (the real
  // fix for the overshoot bug -- see that function's own header comment),
  // so this is a pure safety margin on top of that, not load-bearing: a
  // few px of headroom above the 100 gridline / below the 0 gridline in
  // case of any floating-point-level edge case, not a substitute for the
  // interpolation method fix.
  const width = 260, height = 78, pad = 7;
  const innerHeight = height - pad * 2;
  const scaleMax = 100;
  const stepX = data.length > 1 ? width / (data.length - 1) : 0;
  const points = data.map((d, i) => ({
    x: data.length > 1 ? i * stepX : width / 2,
    y: pad + (1 - Math.min(d.value, scaleMax) / scaleMax) * innerHeight,
  }));

  const linePath = monotoneCubicPath(points);
  const areaPath = `${linePath} L ${points[points.length - 1].x.toFixed(2)},${height} L ${points[0].x.toFixed(2)},${height} Z`;

  // Light gridlines at 0/25/50/75/100 -- reads the absolute severity scale
  // at a glance, which is the whole point of fixing the y-axis to 0-100.
  const gridlines = [0, 0.25, 0.5, 0.75, 1].map(f => {
    const y = (pad + f * innerHeight).toFixed(2);
    return `<line class="chart-gridline" x1="0" y1="${y}" x2="${width}" y2="${y}" />`;
  }).join('');

  const gradientId = `trendFill-${containerId}`;
  const dotsAndHitTargets = points.map((p, i) => {
    const d = data[i];
    const x = p.x.toFixed(2), y = p.y.toFixed(2);
    // Two circles per point: a small visible dot, plus a larger invisible
    // one on top purely as a bigger, easier-to-hit hover target -- the
    // dot itself stays visually small ("small dot markers"), the hit area
    // doesn't have to be.
    return `
      <circle class="chart-dot" cx="${x}" cy="${y}" r="2.5"></circle>
      <circle class="chart-dot-hit" cx="${x}" cy="${y}" r="9"
        data-label="${d.label}" data-value="${Math.round(d.value)}" data-count="${d.count}"
        onmouseenter="showTrendTooltip(event)" onmousemove="positionChartTooltip(event)" onmouseleave="hideChartTooltip()"></circle>
    `;
  }).join('');

  const labels = data.map(d => `<div class="line-chart-label">${d.label}</div>`).join('');

  el.innerHTML = `
    <div class="trend-chart-wrap">
      <div class="trend-chart-yaxis"><span>100</span><span>50</span><span>0</span></div>
      <div class="trend-chart-plot">
        <svg class="line-chart-svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" preserveAspectRatio="none">
          <defs>
            <linearGradient id="${gradientId}" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stop-color="var(--trend)" stop-opacity="0.35" />
              <stop offset="100%" stop-color="var(--trend)" stop-opacity="0" />
            </linearGradient>
          </defs>
          ${gridlines}
          <path d="${areaPath}" fill="url(#${gradientId})" stroke="none" />
          <path d="${linePath}" fill="none" stroke="var(--trend)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
          ${dotsAndHitTargets}
        </svg>
      </div>
    </div>
    <div class="line-chart-labels">${labels}</div>
  `;
}

// Shared hover tooltip for hand-rolled SVG/HTML charts -- one
// #chartTooltip element (index.html), repositioned/repopulated per hover
// rather than one tooltip element per chart. position:fixed, so it's
// placed straight off event.clientX/clientY with no per-chart offset math
// needed. displayChartTooltip() is the shared low-level piece (set
// content, show, position); each chart gets its own thin wrapper
// (showTrendTooltip/showBarChartTooltip) that reads that chart's own
// data-* attributes and formats its own tooltip text -- kept as discrete
// data-* attributes per value (not one HTML blob in a single data
// attribute) purely to avoid quote-escaping a chunk of markup inside an
// HTML attribute value.
function displayChartTooltip(evt, html) {
  const tip = document.getElementById('chartTooltip');
  if (!tip) return;
  tip.innerHTML = html;
  tip.classList.remove('hidden');
  positionChartTooltip(evt);
}
function showTrendTooltip(evt) {
  const { label, value, count } = evt.target.dataset;
  const countNum = Number(count);
  displayChartTooltip(evt, `
    <div class="chart-tooltip-value">Max severity: ${value}</div>
    <div class="chart-tooltip-detail">${label} — ${countNum} alert${countNum === 1 ? '' : 's'}</div>
  `);
}
function showBarChartTooltip(evt) {
  const col = evt.target.closest('.bar-chart-col');
  if (!col) return;
  const { label, value, description } = col.dataset;
  const valueNum = Number(value);
  displayChartTooltip(evt, `
    <div class="chart-tooltip-value">${label}</div>
    <div class="chart-tooltip-detail">${valueNum} trigger${valueNum === 1 ? '' : 's'} in the last 7 days</div>
    ${description ? `<div class="chart-tooltip-desc">${description}</div>` : ''}
  `);
}
function positionChartTooltip(evt) {
  const tip = document.getElementById('chartTooltip');
  if (!tip || tip.classList.contains('hidden')) return;
  const offset = 14;
  const rect = tip.getBoundingClientRect();
  let x = evt.clientX + offset;
  let y = evt.clientY + offset;
  if (x + rect.width > window.innerWidth - 8) x = evt.clientX - rect.width - offset;
  if (y + rect.height > window.innerHeight - 8) y = evt.clientY - rect.height - offset;
  tip.style.left = `${x}px`;
  tip.style.top = `${y}px`;
}
function hideChartTooltip() {
  const tip = document.getElementById('chartTooltip');
  if (tip) tip.classList.add('hidden');
}

// Human-readable name + plain-language explanation per anomaly_type --
// the full real taxonomy confirmed by direct investigation of
// agent_logic/anomaly_detector.py (the single source of every literal
// "type" value an Alert can carry), reused here rather than re-derived.
// Descriptions are grounded in what each rule actually checks (that same
// file's own thresholds/messages), not just a guess at what the name
// might mean. Falls back to the raw anomaly_type string (via
// anomalyTypeLabel below) for any value not in this table, so an
// unrecognized/future type still renders instead of silently vanishing.
const ANOMALY_TYPE_INFO = {
  failed_logins: { label: 'Failed Logins', description: 'Multiple failed login attempts in a row.' },
  usb_insertion: { label: 'USB Insertion', description: 'A USB device was connected and followed by a large file transfer or an install/run from it.' },
  after_hours: { label: 'After Hours', description: 'Employee was active outside normal working hours.' },
  high_file_access: { label: 'High File Access', description: 'An unusually high number of files were accessed in a short window.' },
  access_velocity: { label: 'Access Velocity', description: 'Files were accessed at an unusually fast rate -- a possible sign of bulk copying.' },
  sensitive_ratio: { label: 'Sensitive Ratio', description: 'A high share of the files accessed in the window were sensitive.' },
  department_mismatch: { label: 'Department Mismatch', description: "Sensitive files were accessed outside what's normal for the employee's department." },
  privilege_escalation: { label: 'Privilege Escalation', description: 'An attempt to gain elevated system privileges was detected.' },
  large_print_job: { label: 'Large Print Job', description: 'An unusually large print job was submitted -- a possible sign of data leaving via print.' },
  large_download: { label: 'Large Download', description: 'A large file was downloaded.' },
  unverified_install: { label: 'Unverified Install', description: 'Software was installed from an unverified source.' },
  baseline_deviation: { label: 'Baseline Deviation', description: "Overall activity deviated significantly from this employee's own learned behavioral baseline." },
  time_deviation: { label: 'Time Deviation', description: "Login occurred well outside the normal hours for this employee's department." },
};
function anomalyTypeLabel(type) {
  return (ANOMALY_TYPE_INFO[type] && ANOMALY_TYPE_INFO[type].label) || type;
}
function anomalyTypeDescription(type) {
  return (ANOMALY_TYPE_INFO[type] && ANOMALY_TYPE_INFO[type].description) || '';
}

// Shared renderer for Top Trigger Categories -- data: [{label, value,
// description}] (description optional), already highest-first (the
// backend sorts it). Each column now has a
// GUARANTEED-height label row (.bar-chart-label's own explicit height,
// see style.css) instead of sharing whatever leftover space the value/bar
// happened to leave -- that reserved space is the actual fix for labels
// like "sensitive_ratio" clipping at the card's bottom edge; a label still
// too long for its (possibly narrow, once several categories are shown)
// column truncates with an ellipsis, with the full label + count shown via
// the shared custom tooltip on hover (showBarChartTooltip) rather than a
// native browser title tooltip. Bars sit in a light track (.bar-chart-
// track, --trend-bg) so the unfilled portion of each column is still
// visible, not just blank space -- and use ONE consistent accent color
// (--trend) for every bar, the same token Alerts Over Time uses, not a
// distinct hue per category: a trigger type isn't a severity signal, and a
// rainbow of per-bar colors would read as decorative rather than
// meaningful, which this app deliberately avoids everywhere else.
function renderBarChart(containerId, data, emptyMessage) {
  const el = document.getElementById(containerId);
  if (!el) return;
  if (!data.length || !data.some(d => d.value > 0)) {
    el.innerHTML = `<div class="ai-empty">${emptyMessage}</div>`;
    return;
  }
  const max = Math.max(...data.map(d => d.value), 1);
  el.innerHTML = `
    <div class="bar-chart">
      ${data.map(d => `
        <div class="bar-chart-col"
          data-label="${d.label}" data-value="${d.value}" data-description="${d.description || ''}"
          onmouseenter="showBarChartTooltip(event)" onmousemove="positionChartTooltip(event)" onmouseleave="hideChartTooltip()">
          <div class="bar-chart-value">${d.value}</div>
          <div class="bar-chart-track">
            <div class="bar-chart-bar" style="height:${Math.max(Math.round((d.value / max) * 100), d.value > 0 ? 4 : 0)}%;"></div>
          </div>
          <div class="bar-chart-label">${d.label}</div>
        </div>
      `).join('')}
    </div>
  `;
}

function renderHealthStrip(health) {
  // Renders into the hamburger nav drawer's "System Status" section now
  // (was a full-width strip at the bottom of the Overview page) -- see
  // style.css's .nav-health-item comment for why. Stacked vertically
  // (label+dot on one line, detail below) rather than the old horizontal
  // row, to fit the drawer's 272px width.
  const el = document.getElementById('navHealthStatus');
  if (!el || !health) return;
  const items = [
    { label: 'AI Reasoning Core (LM Studio)', info: health.lm_studio },
    { label: 'Email notifications (SMTP)', info: health.smtp },
    { label: 'Detection scheduler', info: health.scheduler },
  ];
  el.innerHTML = items.map(item => `
    <div class="nav-health-item">
      <span class="health-dot health-${item.info.status}"></span>
      <span class="nav-health-text">
        <span class="nav-health-label">${item.label}</span>
        <span class="nav-health-detail">${item.info.detail}</span>
      </span>
    </div>
  `).join('');
}

async function refreshOverviewExtras() {
  // Separate from refreshAll's 5s poll on purpose: /system/health makes a
  // real network probe against LM Studio each call (see routes/system.py),
  // and the two trend endpoints describe a 7-DAY window that has no
  // reason to be re-queried every 5 seconds -- OVERVIEW_EXTRAS_POLL_MS
  // above is deliberately slower.
  try {
    const [healthRes, dailyRes, byTypeRes] = await Promise.all([
      authFetch('/system/health'),
      authFetch('/alerts/stats/daily'),
      authFetch('/alerts/stats/by-type'),
    ]);
    const health = await healthRes.json();
    const daily = await dailyRes.json();
    const byType = await byTypeRes.json();

    renderHealthStrip(health);
    // max_risk_score (severity) drives the line now, count moved to the
    // hover tooltip -- see backend/routes/alerts.py's alerts_per_day and
    // this file's renderAreaChart for the full reasoning.
    renderAreaChart(
      'alertsOverTimeChart',
      daily.map(d => ({
        label: new Date(d.date + 'T00:00:00Z').toLocaleDateString('en-GB', { weekday: 'short' }),
        value: d.max_risk_score,
        count: d.count,
      })),
      'No alerts in the last 7 days.'
    );
    // Top 10 -- was top 8. The real rule-based taxonomy (agent_logic/
    // anomaly_detector.py) has grown to 13 distinct anomaly_type values
    // (failed_logins, usb_insertion, after_hours, high_file_access,
    // access_velocity, sensitive_ratio, department_mismatch,
    // privilege_escalation, large_print_job, large_download,
    // unverified_install, baseline_deviation, time_deviation); a bar per
    // every one of those every week would make the columns too narrow to
    // read even with truncation. The backend already sorts highest-count
    // first (routes/alerts.py's alerts_by_type, no LIMIT of its own), so
    // this is still "the ones that actually matter" for that week, not an
    // arbitrary cut -- 10 covers the vast majority of realistic weeks
    // while keeping each column wide enough to read.
    renderBarChart(
      'topTriggersChart',
      byType.slice(0, 10).map(d => ({
        label: anomalyTypeLabel(d.anomaly_type),
        value: d.count,
        description: anomalyTypeDescription(d.anomaly_type),
      })),
      'No triggers in the last 7 days.'
    );
  } catch (e) {
    if (e.message !== 'unauthorized') console.error('overview extras refresh failed', e);
  }
}

/* ─────────────────────────────────────────────
   Employee profile page
   ───────────────────────────────────────────── */
let currentProfileDeviceId = null;

// Fetches and fills in the profile page's DOM for `deviceId` -- called
// both by the router (a genuine navigation) and directly by actions taken
// FROM an already-open profile (accept/dismiss/save-edit/offboard/request-
// refresh) that need to refresh what's on screen without changing the
// route. isBackgroundRefresh=true is also how refreshAll()'s 5s poll keeps
// an open profile's risk score, significant events, alert history, and
// reasoning judgments live instead of a one-time snapshot from when it was
// first opened -- it skips rebuilding the bits a background poll shouldn't
// clobber (the Edit Employee form's live input values), the same "don't
// steal focus/in-progress input" lesson as renderPending()'s fix for the
// pending-devices panel.
async function renderProfileData(deviceId, isBackgroundRefresh = false) {
  currentProfileDeviceId = deviceId;

  const res = await authFetch(`/employees/${deviceId}`);
  const data = await res.json();

  // If the admin navigated to a different employee's profile while this
  // fetch was in flight (most likely during a slow background poll),
  // currentProfileDeviceId has already moved on -- applying this response
  // now would flash stale/wrong-employee data over whatever's now on
  // screen. Bail out; the newer call already handled it.
  if (deviceId !== currentProfileDeviceId) return;

  document.getElementById('profileName').innerText = data.label || data.hostname;
  document.getElementById('profileRole').innerText = `${data.department || 'no department'} · ${data.hostname}`;

  // Same "highest-severity unresolved alert" calculation the employee grid
  // uses (currentRiskFor), not a separate most-recent-alert readout — the
  // two used to disagree (grid always showed 0/low due to a device_id type
  // mismatch, this panel showed the real value from a different formula),
  // which looked like two different risk numbers for the same employee.
  // Both now come straight from GET /employees/{id}'s risk_score/
  // risk_level -- the same persisted, continuously-decaying value the
  // grid reads (Device.current_risk_score), not a separate client-side
  // calculation.
  document.getElementById('profileRisk').innerHTML = `
    <div style="font-family:var(--mono);font-variant-numeric:tabular-nums;font-size:48px;font-weight:600;" class="${levelClass(data.risk_level)}">
      ${Math.round(data.risk_score || 0)}
    </div>
    <div style="margin-top:8px;font-size:16px;">
      ${data.risk_level || 'low'} risk
    </div>
  `;
  const isArchived = data.approval_status === 'offboarded';

  // Not an instant pull -- the agent has no listening port (push-only by
  // design). Clicking this sets a flag the device's own next check-in
  // fulfils (routes/device.py's request_device_info_refresh / routes/
  // logs.py's ingest_logs) -- info_refresh_requested (persisted, so it
  // survives a page reload) is what drives which of these two states shows.
  const refreshControl = isArchived
    ? ''
    : data.info_refresh_requested
      ? `<div class="save-hint" style="display:inline-block;margin-top:8px;">Refresh requested — will update on next check-in</div>`
      : `<button class="save-btn" style="margin-top:8px;" onclick="requestDeviceRefresh('${deviceId}')">Refresh device info</button>`;

  // Same live-dot the employee grid uses (style.css's .live-dot/.live-dot.
  // online) -- connection_status is now actually maintained (scheduler.py's
  // _mark_offline_if_stale infers "offline" from check-in staleness, since
  // the agent has no way to push an explicit offline signal), so this dot
  // reflects real connectivity here too, not just on the grid card.
  const connectionDot = `<span class="live-dot ${data.connection_status === 'online' ? 'online' : ''}" style="display:inline-block;vertical-align:middle;margin-right:6px;"></span>`;
  document.getElementById('profileInfo').innerHTML = `
    <div>${connectionDot}Connection: ${data.connection_status}</div><br>
    <div>Last seen: ${data.last_seen ? timestamp(data.last_seen) : 'never'}</div><br>
    <div>OS username: ${data.username || 'unknown'}</div><br>
    <div>IP address: ${data.ip_address || 'unknown'}</div><br>
    <div>OS: ${data.os_info || 'unknown'}</div><br>
    <div>Enrolled: ${data.enrolled_at ? timestamp(data.enrolled_at) : 'unknown'}</div>
    <div>${refreshControl}</div>
  `;

  const banner = document.getElementById('profileArchivedBanner');
  banner.innerHTML = isArchived
    ? `<div class="profile-card" style="border-color:var(--text-dim);"><div class="ai-empty" style="padding:12px 4px;">This employee has been offboarded. Their record is kept as a read-only archive — logs and alert history are preserved, but nothing here can be edited.</div></div>`
    : '';

  const offboardSlot = document.getElementById('profileOffboardSlot');
  offboardSlot.innerHTML = isArchived
    ? ''
    : `<button class="profile-header-btn danger" onclick="offboardEmployee('${deviceId}')">Offboard employee</button>`;

  // Skipped on a background refresh -- rebuilding these inputs every 5s
  // would wipe out a name/department edit the admin has started typing
  // but not yet saved, the same class of bug renderPending()'s focus-loss
  // fix addressed for the pending-devices panel. An explicit call
  // (isBackgroundRefresh=false) always rebuilds it fresh from the server.
  if (!isBackgroundRefresh) {
    const editForm = document.getElementById('profileEditForm');
    if (isArchived) {
      editForm.innerHTML = `<div class="ai-empty">Not editable — archived.</div>`;
    } else {
      editForm.innerHTML = `
        <div class="edit-field">
          <label>Employee name</label>
          <input type="text" id="editLabelInput" value="${data.label || ''}" />
        </div>
        <div class="edit-field">
          <label>Department</label>
          <select id="editDeptSelect">
            <option value="">No department set</option>
            ${departmentOptionsHtml(data.department)}
          </select>
        </div>
        <div class="edit-field">
          <label>Email (optional -- only used for the Notify Employee alert)</label>
          <input type="email" id="editEmailInput" value="${data.email || ''}" autocomplete="email" />
        </div>
        <button class="save-btn" onclick="saveEmployeeEdit('${deviceId}')">Save changes</button>
        <span class="save-hint hidden" id="editSavedHint">Saved</span>
      `;
    }
  }

  renderAlertHistory(deviceId, data.alert_history || []);
  renderNotifyEmployeeArea(deviceId, data, isArchived);
  renderEmployeeNotificationHistory(data.employee_notifications || []);

  const eventsBox = document.getElementById('significantEvents');
  if (!isBackgroundRefresh) eventsBox.innerHTML = '<div class="ai-empty">Loading…</div>';
  try {
    const eventsRes = await authFetch(`/logs/significant?device_id=${deviceId}&limit=25`);
    const events = await eventsRes.json();
    eventsBox.innerHTML = '';
    if (!events.length) {
      eventsBox.innerHTML = '<div class="ai-empty">No significant events for this device yet.</div>';
    } else {
      events.forEach(ev => {
        const row = document.createElement('div');
        row.className = 'history-row';
        const detail = ev.filepath || ev.device_name || ev.action || '';
        row.innerHTML = `
          <div>${timestamp(ev.timestamp)} — ${ev.event_type}${ev.status ? ' (' + ev.status + ')' : ''}${detail ? ' — ' + detail : ''}</div>
        `;
        eventsBox.appendChild(row);
      });
    }
  } catch (e) {
    if (e.message !== 'unauthorized') eventsBox.innerHTML = '<div class="ai-empty">Could not load significant events.</div>';
  }
}

async function requestDeviceRefresh(deviceId) {
  await authFetch(`/device/${deviceId}/request-refresh`, { method: 'POST' });
  // Re-render the still-open profile so the button immediately swaps to
  // the "requested" state -- info_refresh_requested is persisted
  // server-side, so this reflects reality rather than being a purely
  // optimistic local flag that resets on the next reload.
  await renderProfileData(deviceId);
}

/* ─────────────────────────────────────────────
   Raw logs overlay
   ───────────────────────────────────────────── */
let rawLogsOffset = 0;
const RAW_LOGS_PAGE_SIZE = 50;
// Was fetch-once (open, or a Prev/Next click) with no polling at all --
// confirmed as the actual cause of "logs aren't appearing in real time":
// POST /logs/ingest writes synchronously with no delay, and the
// significant-events panel already polls every 5s (fixed last round),
// but this view had nothing tying it to refreshAll()'s poll whatsoever.
let rawLogsOverlayOpen = false;

function openRawLogs() {
  if (!currentProfileDeviceId) return;
  rawLogsOffset = 0;
  rawLogsOverlayOpen = true;
  document.getElementById('rawLogsOverlay').style.display = 'flex';
  loadRawLogsPage();
}
function closeRawLogs() {
  rawLogsOverlayOpen = false;
  document.getElementById('rawLogsOverlay').style.display = 'none';
}
function rawLogsPage(direction) {
  rawLogsOffset = Math.max(0, rawLogsOffset + direction * RAW_LOGS_PAGE_SIZE);
  loadRawLogsPage();
}
async function loadRawLogsPage(isBackgroundRefresh = false) {
  const list = document.getElementById('rawLogsList');
  if (!isBackgroundRefresh) list.innerHTML = '<div class="ai-empty">Loading…</div>';
  try {
    const res = await authFetch(`/logs/raw?device_id=${currentProfileDeviceId}&limit=${RAW_LOGS_PAGE_SIZE}&offset=${rawLogsOffset}`);
    const data = await res.json();
    document.getElementById('rawLogsSubtitle').innerText = `${data.total} total log rows for this device`;
    list.innerHTML = '';
    if (!data.logs.length) {
      list.innerHTML = '<div class="ai-empty">No logs in this range.</div>';
    } else {
      data.logs.forEach(l => {
        const row = document.createElement('div');
        row.className = 'history-row';
        const detail = l.filepath || l.device_name || l.action || l.process_name || '';
        row.innerHTML = `<div>${timestamp(l.timestamp)} — ${l.event_type}${l.status ? ' (' + l.status + ')' : ''}${detail ? ' — ' + detail : ''}</div>`;
        list.appendChild(row);
      });
    }
    const from = data.total === 0 ? 0 : rawLogsOffset + 1;
    const to = Math.min(rawLogsOffset + data.logs.length, data.total);
    document.getElementById('rawLogsPageInfo').innerText = `${from}-${to} of ${data.total}`;
    document.getElementById('rawLogsPrevBtn').disabled = rawLogsOffset === 0;
    document.getElementById('rawLogsNextBtn').disabled = rawLogsOffset + RAW_LOGS_PAGE_SIZE >= data.total;
  } catch (e) {
    if (e.message !== 'unauthorized' && !isBackgroundRefresh) list.innerHTML = '<div class="ai-empty">Could not load raw logs.</div>';
  }
}

/* ─────────────────────────────────────────────
   AI Reasoning Core — merged into Recent Alert History. No separate
   floating card anymore: every alert's own row (or, for a judgment with
   no linked alert, its own standalone row) is the one place its AI
   assessment, decision timeline, and Dismiss/Undo control all live.
   ───────────────────────────────────────────── */
const REASONING_LABELS = {
  dismiss: 'Dismiss (false positive)',
  monitor: 'Monitor',
  alert_only: 'Alert only',
  alert_restrict: 'Alert + restrict',
  escalate_hr: 'Escalate to HR',
};

// Verbs for the merged decision timeline -- covers both legacy
// ReasoningDecision rows (accept/override, and any dismiss rows recorded
// before the dismiss/undo consolidation) and current AlertDecision rows
// (dismiss/undo going forward).
const DECISION_VERBS = {
  accept: 'accepted',
  override: 'overrode',
  dismiss: 'dismissed this',
  undo: 'undid the dismissal on this',
};

// The AI's explanation/recommendation/evidence, inline within a row --
// deliberately carries NO status wording of its own (no "pending review" /
// "dismissed" badge here). Whether a row is dismissed is read from exactly
// one place -- the row's own alert.status (or, for an orphan judgment,
// judgment.status) -- rendered once in the row's summary tag. Two
// independent status indicators on the same row is exactly what risks
// showing a stale one contradicting the other; this only ever shows one.
function judgmentAssessmentHtml(j) {
  const evidence = j.context_snapshot || {};
  const anomalyLines = (evidence.anomalies || [])
    .map(a => `${a.type}: ${a.message}`)
    .join('<br>') || 'none in the triggering window — aggregate crossed from accumulated/decaying prior signals';
  const componentLines = (evidence.risk_components || [])
    .map(c => `${c.anomaly_type} (${c.score.toFixed(1)})`)
    .join(', ') || 'none';

  return `
    <div class="reasoning-header">
      <span class="reasoning-badge">AI Reasoning Core assessment</span>
      <span style="font-size:11px;color:var(--text-dim);">${timestamp(j.triggered_at)}</span>
    </div>
    <div class="reasoning-explanation">${j.explanation}</div>
    <div class="reasoning-recommendation">Recommended: ${REASONING_LABELS[j.recommendation] || j.recommendation}</div>
    <div class="reasoning-meta">
      Confidence: ${j.confidence != null ? Math.round(j.confidence * 100) + '%' : 'n/a'}
      · ${j.critic_changed_judgment ? 'second-opinion pass revised the initial judgment' : 'second-opinion pass confirmed the initial judgment'}
      · triggered at ${j.trigger_risk_level} risk (${Math.round(j.trigger_risk_score)})
      · model: ${j.model_used}
    </div>
    <details>
      <summary style="cursor:pointer;font-size:12px;color:var(--text-dim);margin-bottom:8px;">View evidence this was based on</summary>
      <div class="reasoning-evidence">
        <div><strong>Anomalies:</strong><br>${anomalyLines}</div>
        <div style="margin-top:8px;"><strong>Active risk components:</strong> ${componentLines}</div>
        <div style="margin-top:8px;"><strong>Recent alerts considered:</strong> ${(evidence.recent_alerts || []).length}</div>
        <div style="margin-top:4px;"><strong>Recent significant events considered:</strong> ${(evidence.recent_significant_events || []).length}</div>
      </div>
    </details>
  `;
}

// One combined, chronological timeline per row -- entry.decision_history
// from agent_logic/alert_history.py, already merged/sorted server-side.
function decisionHistoryHtml(decisionHistory) {
  if (!decisionHistory.length) return '';
  return `
    <div class="reasoning-decision-log">
      <strong>Decision history:</strong>
      ${decisionHistory.map(d => `
        <div style="margin-top:6px;">
          ${timestamp(d.decided_at)} — ${d.admin_username || 'unknown admin'} ${DECISION_VERBS[d.decision] || d.decision}${d.action_value ? ` (${REASONING_LABELS[d.action_value] || d.action_value})` : ''}
          ${d.score_snapshot != null ? ` <span style="opacity:.7">[risk component ${d.decision === 'dismiss' ? 'reset from' : 'restored to'} ${Math.round(d.score_snapshot)}]</span>` : ''}
          ${d.reason ? `<br><em>Reason: ${d.reason}</em>` : ''}
        </div>
      `).join('')}
    </div>
  `;
}

// Exactly one control per row: Dismiss (not currently dismissed) or Undo
// (currently dismissed) -- never both, never neither. `kind` is 'alert' or
// 'judgment' (an orphan judgment with no linked alert), selecting which
// pair of endpoints this row's toggle hits; the two-step Dismiss/Undo →
// reason → Confirm interaction itself is identical either way.
function dismissEndpointPath(kind, id) {
  return kind === 'alert' ? `/alerts/${id}/dismiss` : `/reasoning/${id}/dismiss`;
}
function undoEndpointPath(kind, id) {
  return kind === 'alert' ? `/alerts/${id}/undo` : `/reasoning/${id}/undo`;
}

function toggleControlHtml(deviceId, kind, id, isDismissed) {
  const uid = `${kind}-${id}`;
  const label = isDismissed ? 'Undo' : 'Dismiss';
  const confirmLabel = isDismissed ? 'Confirm' : 'Confirm Dismissal';
  const placeholder = isDismissed ? 'Reason for undoing (required)' : 'Reason for dismissing (required)';
  return `
    <div class="reasoning-actions">
      <button class="reasoning-dismiss-btn" id="toggle-start-${uid}" onclick="showToggleConfirm('${kind}', ${id})">${label}</button>
      <div class="hidden" id="toggle-confirm-group-${uid}" style="display:flex;gap:8px;flex:1;min-width:260px;">
        <input type="text" class="reasoning-dismiss-reason" id="toggle-reason-${uid}" placeholder="${placeholder}" style="flex:1;min-width:200px;" />
        <button class="reasoning-dismiss-btn" onclick="confirmToggle('${deviceId}', '${kind}', ${id}, ${isDismissed})">${confirmLabel}</button>
      </div>
    </div>
  `;
}

function showToggleConfirm(kind, id) {
  const uid = `${kind}-${id}`;
  const startBtn = document.getElementById(`toggle-start-${uid}`);
  const group = document.getElementById(`toggle-confirm-group-${uid}`);
  if (startBtn) startBtn.classList.add('hidden');
  if (group) {
    group.classList.remove('hidden');
    const input = document.getElementById(`toggle-reason-${uid}`);
    if (input) input.focus();
  }
}

async function confirmToggle(deviceId, kind, id, wasDismissed) {
  const uid = `${kind}-${id}`;
  const input = document.getElementById(`toggle-reason-${uid}`);
  const reason = (input ? input.value : '').trim();
  if (!reason) { alert(`A reason is required to ${wasDismissed ? 'undo this dismissal' : 'dismiss this'}.`); return; }
  if (!confirm(wasDismissed ? 'Undo this dismissal?' : 'Dismiss this? No action will be taken.')) return;
  const path = wasDismissed ? undoEndpointPath(kind, id) : dismissEndpointPath(kind, id);
  await authFetch(path, { method: 'POST', body: JSON.stringify({ reason }) });
  await renderProfileData(deviceId);
  await refreshAll();
}

// Full re-openable history: every Alert this device ever raised, each
// correlated with whatever ReasoningJudgment(s) it produced (routes/
// employees.py's alert_history), plus any judgment with no linked alert.
// Rendered as <details> rows so an admin can expand any past entry at any
// time -- native, no custom toggle-state JS needed. Preserves which rows
// are currently expanded across a background refresh the same way the rest
// of this profile avoids clobbering in-progress admin state: capture what's
// open by a stable per-entry id before rebuilding, re-apply after.
let renderedHistorySignature = null;

function historyEntryId(entry) {
  if (entry.alert) return `alert-${entry.alert.alert_id}`;
  return `judgment-${entry.judgments[0].judgment_id}`;
}

// Cheap change signature for one history entry -- the row's own dismissed/
// not-dismissed status (alert.status, or judgment.status for an orphan)
// plus decision-timeline length/last-timestamp are enough to detect
// "something here actually changed" without deep-comparing context
// snapshots on every 5s poll.
function entryJudgmentSignature(entry) {
  const statusPart = entry.alert ? entry.alert.status : (entry.judgments[0] ? entry.judgments[0].status : '');
  const history = entry.decision_history || [];
  const lastDecided = history.length ? history[history.length - 1].decided_at : '';
  return `${statusPart}:${history.length}:${lastDecided}`;
}

function renderAlertHistory(deviceId, entries) {
  const signature = entries.map(e => {
    const j = entryJudgmentSignature(e);
    return `${historyEntryId(e)}:${j}`;
  }).join('|');
  if (signature === renderedHistorySignature) return;
  renderedHistorySignature = signature;

  const container = document.getElementById('alertHistory');
  if (!entries.length) {
    container.innerHTML = '<div class="ai-empty">No alerts for this device yet.</div>';
    return;
  }

  const openIds = new Set(
    Array.from(container.querySelectorAll('details.history-entry[open]')).map(el => el.dataset.entryId)
  );

  container.innerHTML = entries.map(entry => {
    const entryId = historyEntryId(entry);
    const a = entry.alert;
    const judgments = entry.judgments || [];
    // The row's single source of truth for dismissed/not-dismissed: the
    // alert's own status when one exists, otherwise the (orphan)
    // judgment's own status. Never derived from judgment status when an
    // alert is present -- see routes/alerts.py's dismiss endpoint
    // docstring for why a linked judgment's status is no longer touched
    // by this toggle at all.
    const kind = a ? 'alert' : 'judgment';
    const controlId = a ? a.alert_id : judgments[0].judgment_id;
    const isDismissed = a ? a.status === 'dismissed' : judgments[0].status === 'dismissed';

    const summaryLeft = a ? `${timestamp(a.created_at)} — ${a.title}` : `${timestamp(judgments[0].triggered_at)} — AI Reasoning Core flagged this device (no single linked alert)`;
    const summaryRight = `${a ? `<span class="tag tag-${levelClass(a.risk_level)}">${a.risk_level}</span> ` : ''}<span class="tag tag-neutral">${isDismissed ? 'dismissed' : 'open'}</span>`;

    const alertDetail = a ? `
      <div style="font-size:12px;color:var(--text-dim);margin-bottom:10px;">
        ${a.description ? `${a.description}<br>` : ''}
        ${(a.anomalies || []).length ? a.anomalies.join('<br>') : ''}
      </div>
    ` : '';

    const assessment = judgments.map(j => judgmentAssessmentHtml(j)).join('');

    return `
      <details class="history-entry" data-entry-id="${entryId}" ${openIds.has(entryId) ? 'open' : ''}>
        <summary class="history-row">
          <div>${summaryLeft}</div>
          <div>${summaryRight}</div>
        </summary>
        <div class="history-entry-body">
          ${alertDetail}
          ${assessment}
          ${decisionHistoryHtml(entry.decision_history || [])}
          ${toggleControlHtml(deviceId, kind, controlId, isDismissed)}
        </div>
      </details>
    `;
  }).join('');
}

/* ─────────────────────────────────────────────
   Notify Employee -- admin-triggered, manual-only alert email direct to
   the employee (backend/routes/device.py's notify_employee). Two
   independent gates before the button is even enabled: the company-wide
   toggle (Company Profile) and this employee having an email on file
   (Edit Employee form) -- both explained inline, not just a disabled
   button with no reason given.
   ───────────────────────────────────────────── */
const NOTIFY_EMPLOYEE_DEFAULT_TEMPLATE = (companyName) =>
  `This is an automated message from ${companyName}'s monitoring system. Some recent activity on your device has been flagged for review under company policy. This does not necessarily mean anything wrong has occurred. Please pause what you're currently doing and contact your manager or supervisor at your earliest convenience to discuss this. This is an automated notification — replies to this address are not monitored.`;

let notifyEmployeeDeviceId = null;

function renderNotifyEmployeeArea(deviceId, data, isArchived) {
  const area = document.getElementById('notifyEmployeeArea');
  if (isArchived) {
    area.innerHTML = '';
    return;
  }
  const toggleOff = !(company && company.employee_notification_enabled);
  const noEmail = !data.email;

  if (toggleOff) {
    area.innerHTML = `<span style="font-size:11.5px;color:var(--text-dim);" title="Turned off in Company Profile">Notify Employee is disabled for this company</span>`;
  } else if (noEmail) {
    area.innerHTML = `<span style="font-size:11.5px;color:var(--text-dim);">No email on file for this employee — add one in Edit Employee to enable this</span>`;
  } else {
    area.innerHTML = `<button class="profile-header-btn" style="padding:6px 11px;font-size:11.5px;" onclick="openNotifyEmployeeOverlay('${deviceId}')">Notify Employee</button>`;
  }
}

function openNotifyEmployeeOverlay(deviceId) {
  notifyEmployeeDeviceId = deviceId;
  const companyName = company ? company.company_name : 'your company';
  document.getElementById('notifyEmployeeMessage').value = NOTIFY_EMPLOYEE_DEFAULT_TEMPLATE(companyName);
  document.getElementById('notifyEmployeeOverlay').style.display = 'flex';
}

function closeNotifyEmployeeOverlay() {
  document.getElementById('notifyEmployeeOverlay').style.display = 'none';
  notifyEmployeeDeviceId = null;
}

async function sendEmployeeNotification() {
  const message = document.getElementById('notifyEmployeeMessage').value;
  if (!message.trim()) { alert('Message cannot be empty.'); return; }
  if (!notifyEmployeeDeviceId) return;

  const res = await authFetch(`/device/${notifyEmployeeDeviceId}/notify-employee`, {
    method: 'POST',
    body: JSON.stringify({ message }),
  });
  if (!res.ok) {
    let detail = 'Could not send this alert.';
    try { const err = await res.json(); detail = err.detail || detail; } catch (e) { /* not JSON */ }
    alert(detail);
    return;
  }
  const result = await res.json();
  closeNotifyEmployeeOverlay();
  if (result.status === 'success') {
    alert('Alert sent.');
  } else {
    alert(`The alert could not be delivered: ${result.error || 'unknown error'}. This attempt has still been recorded on the employee's profile.`);
  }
  await renderProfileData(currentProfileDeviceId);
}

function renderEmployeeNotificationHistory(entries) {
  const container = document.getElementById('employeeNotificationHistory');
  if (!entries.length) {
    container.innerHTML = '';
    return;
  }
  container.innerHTML = `
    <div style="margin-top:14px;padding-top:12px;border-top:1px solid var(--border);">
      <div style="font-size:11px;font-weight:700;color:var(--text-dim);letter-spacing:.05em;text-transform:uppercase;margin-bottom:8px;">Notifications sent to this employee</div>
      ${entries.map(n => `
        <details class="history-entry">
          <summary class="history-row">
            <div>${timestamp(n.sent_at)} — sent by ${n.admin}</div>
            <div><span class="tag ${n.status === 'success' ? 'tag-neutral' : 'tag-critical'}">${n.status}</span></div>
          </summary>
          <div class="history-entry-body">
            <div style="font-size:12px;color:var(--text-dim);white-space:pre-wrap;">${n.message}</div>
            ${n.error ? `<div style="margin-top:6px;font-size:11px;color:var(--critical);">${n.error}</div>` : ''}
          </div>
        </details>
      `).join('')}
    </div>
  `;
}

/* ─────────────────────────────────────────────
   PDF reports -- authenticated blob download. A plain <a href> can't
   carry the Bearer token, so this fetches the PDF as a blob via the same
   authFetch() every other request uses, then triggers a save through a
   throwaway object URL + a synthetic click on a temporary <a download>.
   ───────────────────────────────────────────── */
async function downloadPdf(path, fallbackFilename) {
  const res = await authFetch(path);
  if (!res.ok) {
    let detail = 'Could not generate this report.';
    try { const err = await res.json(); detail = err.detail || detail; } catch (e) { /* not JSON, keep default */ }
    if (res.status !== 401) alert(detail); // authFetch already handled 401 (logout) before returning
    return;
  }
  const blob = await res.blob();
  const disposition = res.headers.get('Content-Disposition') || '';
  const match = disposition.match(/filename="([^"]+)"/);
  const filename = match ? match[1] : fallbackFilename;

  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

// Per-alert report generation (GET /reasoning/{id}/report.pdf) is no
// longer exposed from the AI Reasoning Core card -- the employee-level
// report in the profile header (below) is the only report entry point
// for now. The backend endpoint itself is untouched and still reachable
// directly; there's just no button wired to it here any more.

// Wraps generateEmployeeReport() so index.html's button only ever needs to
// pass `this` -- reads currentProfileDeviceId from inside a real function
// body (the same pattern openRawLogs()/loadRawLogsPage() already use for
// this exact variable) rather than an inline onclick="" attribute
// referencing a top-level `let` binding directly, which is valid JS but
// untested in this codebase's existing patterns -- not worth being the
// first place that relies on it working.
async function generateEmployeeReportFromProfile(btnEl) {
  return generateEmployeeReport(currentProfileDeviceId, btnEl);
}

async function generateEmployeeReport(deviceId, btnEl) {
  if (!deviceId) return;
  const original = btnEl.innerText;
  btnEl.disabled = true;
  // This one makes a real LLM call (backend/reasoning/narrative.py, single-
  // pass) rather than just reading already-computed data -- realistically
  // ~10-20s, not instant like the per-alert report, so the button says so
  // rather than looking hung.
  btnEl.innerText = 'Generating... (~15-20s)';
  try {
    await downloadPdf(`/employees/${deviceId}/report.pdf`, 'litds-employee-report.pdf');
  } finally {
    btnEl.disabled = false;
    btnEl.innerText = original;
  }
}

/* ─────────────────────────────────────────────
   Weekly company-wide report -- start-job / poll-status / fetch-result
   (backend/routes/reports.py). Genuinely long-running (minutes, up to
   ~30 for a larger roster -- one local LLM call per employee-with-
   activity, processed one at a time), so this shows a real progress
   overlay rather than the per-employee report's simple button-text
   change, which would look hung well before a company-wide job finishes.
   ───────────────────────────────────────────── */
const WEEKLY_REPORT_POLL_MS = 1500;

async function generateWeeklyReport(btnEl) {
  const overlay = document.getElementById('weeklyReportOverlay');
  const textEl = document.getElementById('weeklyReportProgressText');
  const fillEl = document.getElementById('weeklyReportProgressFill');

  btnEl.disabled = true;
  overlay.classList.remove('hidden');
  textEl.textContent = 'Starting...';
  fillEl.style.width = '0%';

  try {
    const startRes = await authFetch('/reports/weekly', { method: 'POST' });
    if (!startRes.ok) {
      let detail = 'Could not start the weekly report.';
      try { const err = await startRes.json(); detail = err.detail || detail; } catch (e) { /* not JSON */ }
      alert(detail);
      return;
    }
    const { job_id } = await startRes.json();

    // Poll until done/error -- each tick just reads in-memory job state
    // (routes/reports.py's _jobs), cheap regardless of how long the
    // underlying job takes.
    while (true) {
      await new Promise((resolve) => setTimeout(resolve, WEEKLY_REPORT_POLL_MS));
      const statusRes = await authFetch(`/reports/weekly/${job_id}/status`);
      if (!statusRes.ok) break; // 401 already handled by authFetch (logout); anything else, stop polling rather than loop forever
      const job = await statusRes.json();

      const total = job.total || 0;
      const processed = job.processed || 0;
      const pct = total > 0 ? Math.round((processed / total) * 100) : 0;
      fillEl.style.width = `${pct}%`;
      textEl.textContent = total > 0
        ? `Generating report -- employee ${processed} of ${total}`
        : 'Gathering employee data...';

      if (job.status === 'done') {
        await downloadPdf(`/reports/weekly/${job_id}/result.pdf`, 'litds-weekly-report.pdf');
        break;
      }
      if (job.status === 'error') {
        alert(job.error || 'The weekly report failed to generate. Try again shortly.');
        break;
      }
    }
  } finally {
    overlay.classList.add('hidden');
    btnEl.disabled = false;
  }
}

async function offboardEmployee(deviceId) {
  if (!confirm('Offboard this employee? Their device stops being monitored, but all past logs, alerts, and history are kept as an archive.')) return;
  await authFetch(`/device/${deviceId}/offboard`, { method: 'POST' });
  navigateHome();
  await refreshAll();
}

async function saveEmployeeEdit(deviceId) {
  const label = document.getElementById('editLabelInput').value.trim();
  const department = document.getElementById('editDeptSelect').value;
  const email = document.getElementById('editEmailInput').value.trim();
  if (!label) { alert('Employee name cannot be empty'); return; }
  await authFetch(`/device/${deviceId}`, {
    method: 'PATCH',
    body: JSON.stringify({ label, department: department || null, email: email || null }),
  });
  await refreshAll();
  const hint = document.getElementById('editSavedHint');
  if (hint) { hint.classList.remove('hidden'); setTimeout(() => hint.classList.add('hidden'), 2000); }
  document.getElementById('profileName').innerText = label;
  document.getElementById('profileRole').innerText = `${department || 'no department'} · ${(employees.find(e => deviceIdFor(e) === deviceId) || {}).hostname || ''}`;
}

function copyCompanyCode(sourceId) {
  const code = document.getElementById(sourceId || 'companyCodeBox').innerText;
  navigator.clipboard.writeText(code).catch(() => {});
}

/* ─────────────────────────────────────────────
   Company Profile page (#/company) -- was an overlay/popup (function name
   kept the history in mind: this used to set display:flex on a modal;
   now it just fills in the always-in-DOM #companyView page, visibility
   handled entirely by the router in the Routing section above).
   ───────────────────────────────────────────── */
async function loadCompanyPage() {
  document.getElementById('companyOverlayName').innerText = company ? company.company_name : '';
  document.getElementById('companyOverlayCode').innerText = company ? company.company_code : '';

  const res = await authFetch('/company/smtp');
  const smtp = await res.json();

  const statusEl = document.getElementById('companySmtpStatus');
  const configLine = smtp.configured
    ? `Configured: ${smtp.smtp_username} @ ${smtp.smtp_host}:${smtp.smtp_port}`
    : smtp.would_use_fallback
      ? 'Not configured for this company — using the local .env fallback (dev only, not a real deployment setup).'
      : 'Not configured. Notifications will not be sent until this is set up.';

  // Last real send attempt against THIS company's own config -- visible
  // here so a bad credential (or any other send failure) shows up in the
  // dashboard itself, not only in a server log. Never shown for the
  // .env fallback (notifications/smtp_resolver.py's record_send_result
  // only ever tracks a company-configured send).
  let sendLine = '';
  if (smtp.configured && smtp.last_send_status) {
    const when = timestamp(smtp.last_send_at);
    sendLine = smtp.last_send_status === 'success'
      ? `<div style="margin-top:4px;color:var(--low);">Last send: succeeded — ${when}</div>`
      : `<div style="margin-top:4px;color:var(--critical);">Last send: FAILED — ${when}${smtp.last_send_error ? `<br><span class="mono" style="font-size:11px;">${smtp.last_send_error}</span>` : ''}</div>`;
  } else if (smtp.configured) {
    sendLine = '<div style="margin-top:4px;color:var(--text-dim);">No send attempted yet.</div>';
  }
  statusEl.innerHTML = `<div>${configLine}</div>${sendLine}`;

  const formEl = document.getElementById('companySmtpEditForm');
  // Write is owner-only (routes/company.py's require_owner on PATCH
  // /company/smtp) -- everyone else gets the read-only status line above
  // and no form, not a door to an action that would 403.
  if (me.role !== 'owner') {
    formEl.innerHTML = '';
  } else {
    formEl.innerHTML = `
      <div class="edit-field">
        <label>SMTP host</label>
        <input type="text" id="smtpHostInput" value="${smtp.smtp_host || ''}" autocomplete="off" />
      </div>
      <div class="edit-field">
        <label>SMTP port</label>
        <input type="number" id="smtpPortInput" value="${smtp.smtp_port || 587}" autocomplete="off" />
      </div>
      <div class="edit-field">
        <label>SMTP username</label>
        <input type="text" id="smtpUsernameInput" value="${smtp.smtp_username || ''}" autocomplete="off" />
      </div>
      <div class="edit-field">
        <label>SMTP password${smtp.password_set ? ' (leave blank to keep the current one)' : ''}</label>
        <input type="password" id="smtpPasswordInput" placeholder="${smtp.password_set ? '••••••••••••' : ''}" autocomplete="new-password" />
      </div>
      <button class="save-btn" onclick="saveCompanySmtp()">Save</button>
      <span class="save-hint hidden" id="smtpSavedHint">Saved</span>
    `;
  }

  renderEmployeeNotificationToggle();

  await loadCompanyPolicyDocument();

  // departments is already fresh from refreshAll()'s own 5s poll (it runs
  // regardless of which view is showing) -- this just renders it; see
  // reloadDepartments() for the immediate-refresh path create/remove use
  // so a change shows up right away instead of waiting for the next poll.
  renderDepartmentsList();
}

// Write is owner-only (routes/company.py's require_owner on PATCH
// /company/employee-notifications), same gating as the SMTP form above --
// everyone else gets a plain read-only line, no checkbox that would 403.
// Reads straight off the already-loaded `company` global (extended with
// employee_notification_enabled server-side) rather than a separate
// fetch, since /company/me is already refreshed on every load.
function renderEmployeeNotificationToggle() {
  const area = document.getElementById('employeeNotificationToggleArea');
  const enabled = !!(company && company.employee_notification_enabled);
  if (me.role !== 'owner') {
    area.innerHTML = `<div style="font-size:12.5px;color:var(--text-dim);">Currently ${enabled ? 'enabled' : 'disabled'} for this company. Only the owner can change this.</div>`;
    return;
  }
  area.innerHTML = `
    <label style="display:flex;align-items:center;gap:8px;font-size:13px;">
      <input type="checkbox" id="employeeNotificationToggle" ${enabled ? 'checked' : ''} onchange="saveEmployeeNotificationToggle()" />
      Allow admins to send Notify Employee alerts
    </label>
    <span class="save-hint hidden" id="employeeNotificationSavedHint">Saved</span>
  `;
}

async function saveEmployeeNotificationToggle() {
  const checkbox = document.getElementById('employeeNotificationToggle');
  const res = await authFetch('/company/employee-notifications', {
    method: 'PATCH',
    body: JSON.stringify({ enabled: checkbox.checked }),
  });
  if (!res.ok) {
    checkbox.checked = !checkbox.checked; // revert the visual state on failure
    let detail = 'Could not save this setting.';
    try { const err = await res.json(); detail = err.detail || detail; } catch (e) { /* not JSON */ }
    alert(detail);
    return;
  }
  company = await res.json();
  const hint = document.getElementById('employeeNotificationSavedHint');
  if (hint) { hint.classList.remove('hidden'); setTimeout(() => hint.classList.add('hidden'), 2000); }
}
async function saveCompanySmtp() {
  const host = document.getElementById('smtpHostInput').value.trim();
  const port = parseInt(document.getElementById('smtpPortInput').value, 10);
  const username = document.getElementById('smtpUsernameInput').value.trim();
  const password = document.getElementById('smtpPasswordInput').value;
  if (!host || !port || !username) { alert('Host, port, and username are all required.'); return; }
  const body = { smtp_host: host, smtp_port: port, smtp_username: username };
  if (password) body.smtp_password = password;
  const res = await authFetch('/company/smtp', { method: 'PATCH', body: JSON.stringify(body) });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    alert(err.detail || 'Could not save SMTP settings.');
    return;
  }
  await loadCompanyPage();
  const hint = document.getElementById('smtpSavedHint');
  if (hint) { hint.classList.remove('hidden'); setTimeout(() => hint.classList.add('hidden'), 2000); }
}

/* ─────────────────────────────────────────────
   Company bylaws/policy document -- owner-only upload (drag-and-drop or
   click-to-browse), any admin can view the actual converted text that's
   being fed to the Reasoning Core (routes/company.py's /company/
   policy-document). Read/write split mirrors the SMTP section above.
   ───────────────────────────────────────────── */
async function loadCompanyPolicyDocument() {
  const res = await authFetch('/company/policy-document');
  const doc = await res.json();

  const statusEl = document.getElementById('companyPolicyStatus');
  statusEl.innerText = doc.configured
    ? `Uploaded: ${doc.original_filename} — ${timestamp(doc.uploaded_at)}`
    : 'No policy document uploaded. The Reasoning Core will reason from general behavioral norms only.';

  const areaEl = document.getElementById('companyPolicyUploadArea');
  const viewerHtml = doc.configured ? `
    <details style="margin-top:10px;">
      <summary style="cursor:pointer;font-size:12px;color:var(--text-dim);">View converted text (exactly what's available to the AI)</summary>
      <div class="reasoning-evidence" style="margin-top:8px;max-height:280px;white-space:pre-wrap;">${escapeHtml(doc.converted_markdown)}</div>
    </details>
  ` : '';

  if (me.role !== 'owner') {
    areaEl.innerHTML = viewerHtml;
    return;
  }

  areaEl.innerHTML = `
    <div id="policyDropZone" style="border:1px dashed var(--border-strong);border-radius:var(--radius);padding:18px;text-align:center;font-size:12.5px;color:var(--text-dim);cursor:pointer;">
      Drag a PDF here, or click to browse
      <input type="file" id="policyFileInput" accept="application/pdf" style="display:none;" />
    </div>
    ${doc.configured ? '<button class="profile-header-btn danger" style="margin-top:8px;" onclick="deleteCompanyPolicyDocument()">Remove document</button>' : ''}
    <span class="save-hint hidden" id="policyUploadedHint">Uploaded</span>
    ${viewerHtml}
  `;

  const dropZone = document.getElementById('policyDropZone');
  const fileInput = document.getElementById('policyFileInput');
  dropZone.onclick = () => fileInput.click();
  fileInput.onchange = () => { if (fileInput.files[0]) uploadCompanyPolicyDocument(fileInput.files[0]); };
  dropZone.ondragover = (e) => { e.preventDefault(); dropZone.style.borderColor = 'var(--accent)'; };
  dropZone.ondragleave = () => { dropZone.style.borderColor = 'var(--border-strong)'; };
  dropZone.ondrop = (e) => {
    e.preventDefault();
    dropZone.style.borderColor = 'var(--border-strong)';
    if (e.dataTransfer.files[0]) uploadCompanyPolicyDocument(e.dataTransfer.files[0]);
  };
}

async function uploadCompanyPolicyDocument(file) {
  const formData = new FormData();
  formData.append('file', file);
  // Not authFetch -- that always sets Content-Type: application/json,
  // which would break a multipart upload. The browser sets the correct
  // multipart Content-Type (with boundary) itself when the body is a
  // FormData and no Content-Type header is set explicitly.
  const res = await fetch('/company/policy-document', {
    method: 'POST',
    headers: authHeaders(),
    body: formData,
  });
  if (res.status === 401) { logout(); return; }
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    alert(err.detail || 'Could not upload this document.');
    return;
  }
  await loadCompanyPolicyDocument();
  const hint = document.getElementById('policyUploadedHint');
  if (hint) { hint.classList.remove('hidden'); setTimeout(() => hint.classList.add('hidden'), 2000); }
}

async function deleteCompanyPolicyDocument() {
  if (!confirm('Remove the uploaded policy document? The Reasoning Core will go back to general behavioral norms only.')) return;
  const res = await authFetch('/company/policy-document', { method: 'DELETE' });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    alert(err.detail || 'Could not remove this document.');
    return;
  }
  await loadCompanyPolicyDocument();
}

/* ─────────────────────────────────────────────
   Departments (Company Profile page) -- per-company, admin-managed set
   replacing the old hardcoded DEPARTMENTS list (routes/company.py's
   GET/POST /company/departments, POST /company/departments/{id}/remove).
   Read is open to any admin (the `departments` global is populated by
   refreshAll() regardless of role, since the approve/edit-employee
   dropdowns need it too); only the create/remove actions below are
   owner-gated, same read/write split as SMTP and the policy document.
   ───────────────────────────────────────────── */
async function reloadDepartments() {
  // Immediate refresh for right after a create/remove -- refreshAll()'s
  // own 5s poll would eventually pick this up too, but a newly created or
  // just-removed department showing up instantly (in this list AND the
  // approve/edit-employee dropdowns) reads as far more responsive than
  // waiting out the poll interval.
  const res = await authFetch('/company/departments');
  departments = await res.json();
}

// Edit mode gates BOTH the per-row Remove button and the whole Add-
// department form -- outside edit mode this panel is read-only (names +
// badges only), matching the deliberate "don't show destructive/write
// controls until asked for" pattern already used elsewhere (e.g. the
// dismiss/undo reason field only appearing after its own Dismiss/Undo
// button is clicked). Resets to false every time the page is (re)loaded,
// not persisted -- opening Company Profile always starts read-only.
let departmentsEditMode = false;
function toggleDepartmentsEditMode() {
  departmentsEditMode = !departmentsEditMode;
  editingDepartmentId = null; // don't leave a row's inline edit form open across a mode toggle
  renderDepartmentsList();
}

// Which single department (by id) currently has its inline edit form open
// -- at most one at a time, same "one thing open" restraint as the
// dismiss/undo reason field elsewhere in this file. null when none.
let editingDepartmentId = null;
function startEditDepartment(departmentId) {
  editingDepartmentId = departmentId;
  renderDepartmentsList();
}
function cancelEditDepartment() {
  editingDepartmentId = null;
  renderDepartmentsList();
}
async function saveDepartmentEdit(departmentId) {
  const keywords = document.getElementById(`editDeptKeywordsInput-${departmentId}`).value.trim();
  const fullAccess = document.getElementById(`editDeptFullAccessCheckbox-${departmentId}`).checked;
  const res = await authFetch(`/company/departments/${departmentId}/update`, {
    method: 'POST',
    body: JSON.stringify({ allowed_sensitive_keywords: keywords || null, full_sensitive_access: fullAccess }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    alert(err.detail || 'Could not update this department.');
    return;
  }
  editingDepartmentId = null;
  await reloadDepartments();
  renderDepartmentsList();
}
// Inline edit form for one existing department -- keywords + full-access
// flag only, same fields DepartmentCreateRequest accepts (minus name).
// The name itself renders as plain text, not an input -- see
// backend/routes/company.py's update_department docstring for why
// renaming isn't offered here at all: DeviceMetadata.department stores
// the name as a plain string, so changing it would orphan every employee
// currently pointing at the old value.
function departmentEditRowHtml(d) {
  const keywordsValue = (d.allowed_sensitive_keywords || []).join(', ');
  return `
    <div class="history-row" style="flex-direction:column;align-items:stretch;gap:8px;">
      <div>${departmentLabel(d.name)} <span style="color:var(--text-faint);font-weight:400;font-size:11px;">(name can't be changed)</span></div>
      <div class="edit-field">
        <label>Allowed sensitive-content keywords (comma-separated, optional -- leave blank for no special access)</label>
        <input type="text" id="editDeptKeywordsInput-${d.id}" value="${keywordsValue}" autocomplete="off" />
      </div>
      <div class="edit-field" style="display:flex;align-items:center;gap:8px;">
        <input type="checkbox" id="editDeptFullAccessCheckbox-${d.id}" style="width:auto;" ${d.full_sensitive_access ? 'checked' : ''} />
        <label style="margin:0;">Full sensitive-content access (e.g. executive, compliance/audit roles) -- overrides the keyword field above</label>
      </div>
      <div style="display:flex;gap:8px;">
        <button class="save-btn" onclick="saveDepartmentEdit(${d.id})">Save</button>
        <button class="profile-header-btn" style="padding:6px 11px;font-size:11.5px;" onclick="cancelEditDepartment()">Cancel</button>
      </div>
    </div>
  `;
}

function renderDepartmentsList() {
  const list = document.getElementById('departmentsList');
  // Removed (is_active=false) departments are a frontend/display filter
  // only -- the row itself stays in the database exactly as soft-deleted
  // (models/department.py), and agent_logic/departments.py's lookups
  // still resolve it for whoever might still reference its name; this
  // view just never shows it once removed, no faded/struck-through
  // remnant.
  const active = activeDepartments();

  const editBtn = `<button class="profile-header-btn" style="padding:6px 11px;font-size:11.5px;" onclick="toggleDepartmentsEditMode()">${departmentsEditMode ? 'Done' : 'Edit'}</button>`;

  if (!active.length) {
    list.innerHTML = `<div style="display:flex;justify-content:flex-end;margin-bottom:8px;">${me.role === 'owner' ? editBtn : ''}</div><div class="ai-empty">No departments configured yet.</div>`;
  } else {
    const rows = active.map(d => {
      if (editingDepartmentId === d.id) return departmentEditRowHtml(d);
      return `
      <div class="history-row">
        <div>
          ${departmentLabel(d.name)}
          ${d.full_sensitive_access ? ' <span class="tag tag-neutral">full sensitive access</span>' : ''}
        </div>
        ${(departmentsEditMode && me.role === 'owner') ? `
          <div style="display:flex;gap:6px;flex:none;">
            <button class="profile-header-btn" style="padding:6px 11px;font-size:11.5px;" onclick="startEditDepartment(${d.id})">Edit</button>
            <button class="profile-header-btn danger" style="padding:6px 11px;font-size:11.5px;" onclick="removeDepartment(${d.id}, '${departmentLabel(d.name).replace(/'/g, "\\'")}')">Remove</button>
          </div>
        ` : ''}
      </div>
    `;
    }).join('');
    list.innerHTML = `<div style="display:flex;justify-content:flex-end;margin-bottom:8px;">${me.role === 'owner' ? editBtn : ''}</div>${rows}`;
  }

  const createArea = document.getElementById('departmentCreateArea');
  // Write is owner-only (routes/company.py's require_owner on POST
  // /company/departments and .../remove) -- same gating as SMTP/policy-
  // document. Also hidden entirely outside edit mode, even for an owner.
  if (me.role !== 'owner' || !departmentsEditMode) {
    createArea.innerHTML = '';
    return;
  }

  // Autocomplete suggestions for the keyword field -- drawn from every
  // keyword already used across this company's own active departments, a
  // <datalist> (not a fresh fetch, just this company's already-loaded
  // `departments`) so a new department gets a consistency nudge instead
  // of a blank field, without turning this into a fixed/closed vocabulary
  // -- any text is still accepted, this only ever suggests.
  const existingKeywords = Array.from(new Set(active.flatMap(d => d.allowed_sensitive_keywords || []))).sort();
  const datalistHtml = `<datalist id="departmentKeywordsDatalist">${existingKeywords.map(k => `<option value="${k}"></option>`).join('')}</datalist>`;

  createArea.innerHTML = `
    <div style="margin-top:16px;padding-top:14px;border-top:1px solid var(--border);">
      <div class="profile-card-title" style="margin-bottom:10px;">Add a department</div>
      <div class="edit-field">
        <label>Name</label>
        <input type="text" id="newDeptNameInput" autocomplete="off" />
      </div>
      <div class="edit-field">
        <label>Allowed sensitive-content keywords (comma-separated, optional -- leave blank for no special access)</label>
        <input type="text" id="newDeptKeywordsInput" placeholder="e.g. payroll, salary, contract" autocomplete="off" list="departmentKeywordsDatalist" />
        ${datalistHtml}
      </div>
      <div class="edit-field" style="display:flex;align-items:center;gap:8px;">
        <input type="checkbox" id="newDeptFullAccessCheckbox" style="width:auto;" />
        <label style="margin:0;">Full sensitive-content access (e.g. executive, compliance/audit roles) -- overrides the keyword field above</label>
      </div>
      <button class="save-btn" onclick="createDepartment()">Add department</button>
      <span class="save-hint hidden" id="departmentCreatedHint">Added</span>
    </div>
  `;
}

async function createDepartment() {
  const name = document.getElementById('newDeptNameInput').value.trim();
  const keywords = document.getElementById('newDeptKeywordsInput').value.trim();
  const fullAccess = document.getElementById('newDeptFullAccessCheckbox').checked;
  if (!name) { alert('Enter a department name.'); return; }

  const res = await authFetch('/company/departments', {
    method: 'POST',
    body: JSON.stringify({ name, allowed_sensitive_keywords: keywords || null, full_sensitive_access: fullAccess }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    alert(err.detail || 'Could not create this department.');
    return;
  }
  await reloadDepartments();
  renderDepartmentsList();
  const hint = document.getElementById('departmentCreatedHint');
  if (hint) { hint.classList.remove('hidden'); setTimeout(() => hint.classList.add('hidden'), 2000); }
}

async function removeDepartment(departmentId, label) {
  if (!confirm(`Remove the "${label}" department? Anyone currently assigned to it will be set to "No department set".`)) return;
  const res = await authFetch(`/company/departments/${departmentId}/remove`, { method: 'POST' });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    alert(err.detail || 'Could not remove this department.');
    return;
  }
  const result = await res.json();
  await reloadDepartments();
  renderDepartmentsList();
  if (result.assigned_employee_count > 0) {
    alert(`${result.assigned_employee_count} employee(s) were in "${label}" and have been set to "No department set".`);
  }
}

/* ─────────────────────────────────────────────
   Archived employees overlay
   ───────────────────────────────────────────── */
function openArchiveOverlay() {
  const list = document.getElementById('archiveList');
  list.innerHTML = '';
  if (!archivedEmployees.length) {
    list.innerHTML = '<div class="ai-empty">No offboarded employees yet.</div>';
  } else {
    archivedEmployees.forEach(emp => {
      const row = document.createElement('div');
      row.className = 'history-row';
      row.style.cursor = 'pointer';
      row.innerHTML = `
        <div>${emp.label || emp.hostname} — ${emp.department || 'no department'}</div>
        <div style="color:var(--text-dim);">${emp.hostname}</div>
      `;
      row.onclick = () => { closeArchiveOverlay(); navigateToEmployee(deviceIdFor(emp)); };
      list.appendChild(row);
    });
  }
  document.getElementById('archiveOverlay').style.display = 'flex';
}
function closeArchiveOverlay() {
  document.getElementById('archiveOverlay').style.display = 'none';
}

/* ─────────────────────────────────────────────
   My account -- every admin's own profile + self-service device link +
   self-service password change (routes/admin.py's /admin/me,
   /admin/link-device, /admin/me/password).
   ───────────────────────────────────────────── */
async function openMyAccountOverlay() {
  document.getElementById('myAccountOverlay').style.display = 'flex';
  const res = await authFetch('/admin/me');
  const profile = await res.json();
  document.getElementById('myAccountInfo').innerHTML = `
    <div>Username: ${profile.username}</div><br>
    <div>Role: ${profile.role}</div><br>
    <div>Linked device: ${profile.linked_device_label || 'not linked yet'}</div>
  `;

  const linkCard = document.getElementById('myAccountLinkCard');
  // Hidden once linked (nothing left to do here), AND for the owner
  // account specifically -- routes/admin.py's link_my_device refuses an
  // owner outright (it's account-management only, never meant to be a
  // daily-use identity), so there's no point offering a control here that
  // would just 403. Not the real boundary (that's server-side), just not
  // showing a door to an action that would fail.
  if (profile.linked_device_id || profile.role === 'owner') {
    linkCard.classList.add('hidden');
  } else {
    linkCard.classList.remove('hidden');
    // Not pre-filtered against every other admin's own linked device (that
    // list is owner-only, GET /admin -- a plain admin/manager role can't
    // read it, and shouldn't need to just to see their own account). Every
    // approved device is offered; POST /admin/link-device below still
    // validates server-side and this only ever runs once per admin anyway
    // (the card hides itself the moment linked_device_id is set).
    const approved = devices.filter(d => d.approval_status === 'approved');
    const select = document.getElementById('myAccountDeviceSelect');
    select.innerHTML = approved.length
      ? approved.map(d => `<option value="${d.device_id}">${d.label || d.hostname}</option>`).join('')
      : '<option value="">No approved devices yet</option>';
  }

  // Hard-blocked for owner, not just default-off -- same precedent as the
  // link-device card above (PATCH /admin/me/notifications 403s an owner
  // outright, see that route's own docstring): notifications are a
  // daily-use-account feature, and the owner account exists specifically
  // to stay out of daily routine exposure.
  const notifCard = document.getElementById('myAccountNotificationsCard');
  if (profile.role === 'owner') {
    notifCard.classList.add('hidden');
  } else {
    notifCard.classList.remove('hidden');
    document.getElementById('myAccountEmailInput').value = profile.email || '';
    document.getElementById('myAccountNotificationsToggle').checked = profile.email_notifications_enabled;
  }
}
function closeMyAccountOverlay() {
  document.getElementById('myAccountOverlay').style.display = 'none';
}
async function linkMyDevice() {
  const deviceId = document.getElementById('myAccountDeviceSelect').value;
  if (!deviceId) { alert('No device selected.'); return; }
  const res = await authFetch('/admin/link-device', {
    method: 'POST',
    body: JSON.stringify({ device_public_id: deviceId }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    alert(err.detail || 'Could not link device.');
    return;
  }
  await openMyAccountOverlay();
}
async function changeMyPassword() {
  const current = document.getElementById('currentPasswordInput').value;
  const next = document.getElementById('newPasswordInput').value;
  if (!current || !next) { alert('Both fields are required.'); return; }
  if (next.length < 8) { alert('New password must be at least 8 characters.'); return; }
  const res = await authFetch('/admin/me/password', {
    method: 'PATCH',
    body: JSON.stringify({ current_password: current, new_password: next }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    alert(err.detail || 'Could not change password.');
    return;
  }
  document.getElementById('currentPasswordInput').value = '';
  document.getElementById('newPasswordInput').value = '';
  const hint = document.getElementById('passwordChangedHint');
  hint.classList.remove('hidden');
  setTimeout(() => hint.classList.add('hidden'), 2000);
}
async function saveMyNotificationSettings() {
  const email = document.getElementById('myAccountEmailInput').value.trim();
  const enabled = document.getElementById('myAccountNotificationsToggle').checked;
  if (enabled && !email.includes('@')) { alert('A valid email is required to enable notifications.'); return; }
  const res = await authFetch('/admin/me/notifications', {
    method: 'PATCH',
    body: JSON.stringify({ email: email || null, email_notifications_enabled: enabled }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    alert(err.detail || 'Could not save notification settings.');
    return;
  }
  const hint = document.getElementById('notificationSettingsSavedHint');
  hint.classList.remove('hidden');
  setTimeout(() => hint.classList.add('hidden'), 2000);
}

/* ─────────────────────────────────────────────
   Admin accounts (manager-only) -- roster + promoting an already-approved
   device into a new admin login (routes/admin.py's GET /admin, POST
   /admin/promote).
   ───────────────────────────────────────────── */
async function openAdminAccountsOverlay() {
  document.getElementById('adminAccountsOverlay').style.display = 'flex';
  const res = await authFetch('/admin');
  const admins = await res.json();

  const list = document.getElementById('adminAccountsList');
  // GET /admin now returns every admin this company has ever had, active
  // or removed (routes/admin.py's remove_admin is a soft is_active=False,
  // never a hard delete) -- an inactive row renders greyed with a
  // "Removed" tag instead of silently disappearing, so the owner can see
  // who's been removed, not just who's currently active. No Remove
  // button on an already-inactive row, on the owner's own row (self-
  // removal is blocked server-side anyway), or on any other owner row.
  list.innerHTML = admins.map(a => `
    <div class="history-row" style="${a.is_active ? '' : 'opacity:.5;'}">
      <div>${a.username} <span class="tag tag-neutral" style="margin-left:6px;">${a.role}</span>${a.is_active ? '' : ' <span class="tag tag-neutral">removed</span>'}</div>
      <div style="display:flex;align-items:center;gap:10px;">
        <span class="mono" style="color:var(--text-dim);">${a.linked_device_label || 'not linked'}</span>
        ${(a.is_active && a.role !== 'owner') ? `<button class="profile-header-btn danger" style="padding:6px 11px;font-size:11.5px;" onclick="removeAdmin(${a.admin_id}, '${a.username}')">Remove</button>` : ''}
      </div>
    </div>
  `).join('') || '<div class="ai-empty">No admins found.</div>';

  // Excludes devices already linked to another (active) admin. A removed
  // admin's linked_device_id is always cleared by remove_admin, so this
  // filter naturally re-includes their old device as eligible again.
  const linkedDeviceIds = new Set(admins.filter(a => a.linked_device_id).map(a => a.linked_device_id));
  const eligible = devices.filter(d => d.approval_status === 'approved' && !linkedDeviceIds.has(d.device_id));
  const select = document.getElementById('promoteDeviceSelect');
  select.innerHTML = eligible.length
    ? eligible.map(d => `<option value="${d.device_id}">${d.label || d.hostname}</option>`).join('')
    : '<option value="">No eligible devices -- approve a device first</option>';
}
function closeAdminAccountsOverlay() {
  document.getElementById('adminAccountsOverlay').style.display = 'none';
}
async function promoteDevice() {
  const deviceId = document.getElementById('promoteDeviceSelect').value;
  const username = document.getElementById('promoteUsernameInput').value.trim();
  const email = document.getElementById('promoteEmailInput').value.trim();
  const password = document.getElementById('promotePasswordInput').value;
  const role = document.getElementById('promoteRoleSelect').value;
  if (!deviceId) { alert('No eligible device selected.'); return; }
  if (!username) { alert('Enter a username.'); return; }
  if (!email.includes('@')) { alert('Enter a valid email.'); return; }
  if (password.length < 8) { alert('Password must be at least 8 characters.'); return; }
  const res = await authFetch('/admin/promote', {
    method: 'POST',
    body: JSON.stringify({ device_public_id: deviceId, username, email, password, role }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    alert(err.detail || 'Could not create admin account.');
    return;
  }
  document.getElementById('promoteUsernameInput').value = '';
  document.getElementById('promoteEmailInput').value = '';
  document.getElementById('promotePasswordInput').value = '';
  await openAdminAccountsOverlay();
}
async function removeAdmin(adminId, username) {
  if (!confirm(`Remove ${username}'s admin account? They will no longer be able to log in. This does not delete their past decision history.`)) return;
  const res = await authFetch(`/admin/${adminId}/remove`, { method: 'POST' });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    alert(err.detail || 'Could not remove this admin.');
    return;
  }
  await openAdminAccountsOverlay();
}

/* ─────────────────────────────────────────────
   Boot
   ───────────────────────────────────────────── */
(async function boot() {
  applyThemeControlsState(); // reflect whatever index.html's inline head script already applied
  updateEmployeeViewControls(); // reflect persisted list/grid view-mode choice onto the toggle controls
  if (token) {
    try {
      await enterApp();
    } catch (e) {
      logout();
    }
  }
})();
