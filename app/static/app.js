(() => {
  'use strict';

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
  const state = {user: null, csrf: '', tasks: [], view: 'overview', filter: 'all', taskId: null, task: null, events: [], listTimer: null, detailTimer: null, toastTimer: null, session: 0, listSequence: 0, execution: null, apiConnected: false};
  const viewNames = {overview: '概览', create: '新建任务', history: '任务历史', detail: '任务详情', users: '客户管理', cloudflare: '域名与 DNS'};
  const cf = {configuration: null, zones: [], records: [], zone: null, recordLimit: 100, configSequence: 0, recordSequence: 0, editorRecord: null, recordSaving: false, focusReturn: null};
  const domainAccess = {user: null, zones: [], selected: new Set(), sequence: 0, saving: false, focusReturn: null};
  const editableDNSTypes = new Set(['A', 'AAAA', 'CNAME', 'TXT', 'MX']);
  const stageNames = {
    dns: '检查域名解析', ports: '检查公网端口', download: '下载安装脚本',
    import: '恢复迁移数据库',
    queued: '等待执行', pending: '等待执行', starting: '准备执行', preflight: '服务器环境检查', connect: '连接目标服务器', connecting: '连接目标服务器', validation: '校验输入与数据库', validate: '校验输入与数据库', checking: '服务器环境检查', backup: '备份现有配置', preparing: '准备安装环境', prepare: '准备安装环境', install: '安装 3x-ui', installing: '安装 3x-ui', certificate: '申请与配置 SSL 证书', ssl: '申请与配置 SSL 证书', tls: '配置 HTTPS', acme: '申请 SSL 证书', bbr: '检查与开启 BBR', upload: '上传迁移数据库', restore: '恢复迁移数据库', restoring: '恢复迁移数据库', migrate: '恢复迁移数据库', migrating: '恢复迁移数据库', configure: '设置面板访问与账号', configuring: '设置面板访问与账号', restart: '重启面板服务', reboot: '重启目标服务器', rebooting: '重启目标服务器', waiting_reboot: '等待服务器恢复', reconnect: '等待服务器恢复', verify: '验证交付结果', verifying: '验证交付结果', healthcheck: '验证服务与访问', complete: '任务完成', completed: '任务完成', done: '任务完成', succeeded: '任务完成', failed: '执行失败', interrupted: '执行进程中断', rollback: '恢复备份', cleanup: '清理临时文件'
  };

  function node(tag, className, text) {
    const value = document.createElement(tag);
    if (className) value.className = className;
    if (text !== undefined && text !== null) value.textContent = String(text);
    return value;
  }
  function setText(selector, value) { const target = $(selector); if (target) target.textContent = value == null ? '—' : String(value); }
  function showError(selector, message) { const target = $(selector); target.textContent = message; target.hidden = !message; }
  function errorMessage(value) {
    if (!value) return '操作未完成，请稍后重试。';
    if (typeof value === 'string') return value;
    if (Array.isArray(value)) return value.map(item => typeof item === 'object' ? `${(item.loc || []).filter(part => part !== 'body').join(' / ')}：${item.msg || '输入有误'}` : String(item)).join('；');
    if (typeof value === 'object') return errorMessage(value.message || value.error || value.detail || '服务器返回了错误，请查看任务日志。');
    return String(value);
  }
  function dateTime(value, short = false) {
    if (!value) return '—';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return String(value);
    return new Intl.DateTimeFormat('zh-CN', {month: '2-digit', day: '2-digit', ...(short ? {} : {year: 'numeric'}), hour: '2-digit', minute: '2-digit', hour12: false}).format(date);
  }
  function logTime(value) { const date = new Date(value); return Number.isNaN(date.getTime()) ? '—' : date.toLocaleTimeString('zh-CN', {hour12: false}); }
  function statusType(value) {
    if (['succeeded', 'success', 'completed', 'complete', 'done'].includes(value)) return 'success';
    if (['failed', 'error', 'cancelled', 'canceled', 'interrupted'].includes(value)) return 'failed';
    if (['queued', 'pending'].includes(value)) return 'queued';
    if (['running', 'in_progress', 'waiting_reboot', 'rebooting'].includes(value)) return 'running';
    return 'unknown';
  }
  function statusLabel(value) {
    return {succeeded: '已完成', success: '已完成', completed: '已完成', complete: '已完成', done: '已完成', failed: '执行失败', error: '执行失败', interrupted: '执行中断', cancelled: '已取消', canceled: '已取消', queued: '排队中', pending: '待执行', running: '执行中', in_progress: '执行中', waiting_reboot: '等待重启恢复', rebooting: '正在重启'}[value] || value || '未知状态';
  }
  function badge(value) { return node('span', `badge ${statusType(value)}`, statusLabel(value)); }
  function isActive(task) { return task && ['queued', 'running'].includes(statusType(task.status)); }
  function stageLabel(value) { return stageNames[value] || value || '等待执行'; }
  function taskKind(task) { return task.kind === 'migrate' ? '数据迁移' : '全新部署'; }
  function setConnection(connected) {
    state.apiConnected = connected;
    renderExecution();
  }
  function executionBlocked() { return state.execution?.available === false; }
  function executionMessage() {
    return state.execution?.message || (state.execution?.enabled === false ? '任务执行器尚未启用，暂时不能创建或重试部署任务。请联系管理员。' : '任务执行器暂不可用，请等待恢复后重试。');
  }
  function applySubmissionState() {
    [['#task-form', '#task-runtime-message'], ['#retry-form', '#retry-runtime-message']].forEach(([formSelector, messageSelector]) => {
      const button = $('button[type="submit"]', $(formSelector));
      const blocked = executionBlocked();
      button.disabled = button.dataset.busy === 'true' || blocked;
      button.classList.toggle('runtime-disabled', blocked);
      button.title = blocked ? executionMessage() : '';
      const message = $(messageSelector); message.hidden = !blocked; message.textContent = blocked ? executionMessage() : '';
    });
  }
  function renderExecution() {
    const target = $('#connection-status');
    const execution = state.execution;
    let label = '执行状态未知'; let tone = 'unknown';
    if (!state.apiConnected) { label = 'API 连接不可用'; tone = 'offline'; }
    else if (execution?.enabled === false) { label = '执行器未启用'; tone = 'unavailable'; }
    else if (execution?.available === false) { label = '执行器不可用'; tone = 'unavailable'; }
    else if (execution?.available === true) { label = '可执行'; tone = 'ready'; }
    target.className = `connection-status ${tone}`;
    target.replaceChildren(node('span', 'status-dot'), document.createTextNode(label));
    target.title = state.apiConnected ? execution?.message || 'API 已连接，服务未返回执行器状态。' : '无法连接网站 API，执行器状态暂无法刷新。';
    const notice = $('#execution-notice'); notice.hidden = !executionBlocked();
    setText('#execution-notice-text', executionBlocked() ? executionMessage() : '');
    applySubmissionState();
    if (state.task && state.view === 'detail') renderQueueInfo(state.task);
  }
  function receiveExecution(data) {
    if (Object.prototype.hasOwnProperty.call(data, 'execution')) state.execution = data.execution && typeof data.execution === 'object' ? data.execution : null;
    setConnection(true);
  }
  function toast(message) {
    setText('#toast', message); $('#toast').hidden = false;
    clearTimeout(state.toastTimer); state.toastTimer = setTimeout(() => { $('#toast').hidden = true; }, 3400);
  }
  function setBusy(form, busy, label) {
    const button = $('button[type="submit"]', form);
    if (!button) return;
    if (busy) { if (button.dataset.busy !== 'true') button.dataset.originalLabel = button.textContent; button.textContent = label || '正在处理…'; }
    else if (button.dataset.originalLabel) { button.textContent = button.dataset.originalLabel; delete button.dataset.originalLabel; }
    button.dataset.busy = String(busy);
    button.disabled = busy;
    if (form.id === 'task-form' || form.id === 'retry-form') applySubmissionState();
  }
  function endSession() {
    state.session += 1; state.user = null; state.csrf = ''; state.tasks = []; state.taskId = null; state.task = null; state.events = []; state.execution = null;
    clearTimeout(state.listTimer); clearTimeout(state.detailTimer);
    $('#app-shell').hidden = true; $('#login-screen').hidden = false; $('#boot-screen').hidden = true;
    $('#task-form').reset(); $('#retry-form').reset(); $('#create-user-form').reset();
    resetCloudflare();
    ['#recent-tasks', '#history-tasks', '#task-logs', '#detail-info', '#task-stages', '#users-list', '#result-warnings', '#result-checks', '#result-meta'].forEach(selector => $(selector).replaceChildren());
    $('#result-url').removeAttribute('href'); setText('#result-url', ''); setText('#result-username', '—'); setText('#result-password', '—');
    $('#queue-notice').hidden = true; updateTaskForm(); showFile(); closeMenu(); renderExecution();
  }
  async function api(path, options = {}) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30000);
    const method = options.method || 'GET';
    const headers = new Headers(options.headers || {});
    headers.set('Accept', 'application/json');
    if (method !== 'GET' && method !== 'HEAD') headers.set('X-CSRF-Token', state.csrf);
    let body = options.body;
    if (body && !(body instanceof FormData)) { headers.set('Content-Type', 'application/json'); body = JSON.stringify(body); }
    try {
      const response = await fetch(path, {...options, method, body, headers, credentials: 'same-origin', cache: 'no-store', signal: controller.signal});
      let data = {};
      if (response.status !== 204) {
        const text = await response.text();
        try { data = text ? JSON.parse(text) : {}; } catch { throw new Error(`服务暂时无法响应（HTTP ${response.status}），请稍后重试。`); }
      }
      if (typeof data.csrf_token === 'string') state.csrf = data.csrf_token;
      if (response.status === 503 && method === 'POST' && /^\/api\/tasks(?:\/[^/]+\/retry)?$/.test(path) && !data.execution) {
        data.execution = {...state.execution, available: false, state: 'unavailable', message: errorMessage(data.detail || data.message || '任务执行器暂不可用。')};
      }
      receiveExecution(data);
      if (!response.ok) {
        if (response.status === 401 && state.user && path !== '/api/login') { endSession(); showError('#login-error', '登录已过期，请重新登录。'); }
        throw new Error(errorMessage(data.detail || data.error || data.message || `请求失败（HTTP ${response.status}）`));
      }
      return data;
    } catch (error) {
      if (error.name === 'AbortError') { setConnection(false); throw new Error('请求超时，请检查网络后重试。'); }
      if (error instanceof TypeError) { setConnection(false); throw new Error('无法连接服务，请检查网络或稍后重试。'); }
      throw error;
    } finally { clearTimeout(timeout); }
  }

  function showApp(user) {
    state.session += 1; state.user = user;
    const username = user.username || '用户';
    setText('#sidebar-username', username); setText('#topbar-username', username);
    setText('#sidebar-role', user.role === 'admin' ? '管理员' : '客户账号');
    setText('#user-avatar', username.slice(0, 1).toUpperCase()); setText('#topbar-avatar', username.slice(0, 1).toUpperCase());
    $('#admin-nav').hidden = user.role !== 'admin';
    $('#cloudflare-nav').hidden = false;
    $('#cf-admin-config').hidden = user.role !== 'admin';
    setText('#cf-page-description', user.role === 'admin' ? '管理 Cloudflare 域名解析，并在客户管理中分配可操作域名。' : '管理分配给你的域名解析，每个域名最多 100 条记录。');
    $('#boot-screen').hidden = true; $('#login-screen').hidden = true; $('#app-shell').hidden = false;
    $('#login-password').value = '';
    changeView('overview'); loadTasks();
  }
  function closeMenu() { $('#sidebar').classList.remove('open'); $('#sidebar-backdrop').hidden = true; $('#menu-button').setAttribute('aria-expanded', 'false'); }
  function changeView(name) {
    if (!state.user) return;
    if (!viewNames[name] || name === 'users' && state.user.role !== 'admin') name = 'overview';
    if (name !== 'cloudflare') closeDNSEditor();
    if (name !== 'users') closeDomainAccess();
    if (name !== 'detail') { clearTimeout(state.detailTimer); state.taskId = null; }
    state.view = name;
    $$('.view').forEach(view => { view.hidden = view.id !== `${name}-view`; });
    $$('.nav-item').forEach(item => { const active = item.dataset.view === (name === 'detail' ? 'history' : name); item.classList.toggle('active', active); if (active) item.setAttribute('aria-current', 'page'); else item.removeAttribute('aria-current'); });
    setText('#page-label', viewNames[name]); closeMenu();
    if (name === 'history') renderTasks();
    if (name === 'users') loadUsers();
    if (name === 'cloudflare') loadCloudflare();
    window.scrollTo({top: 0, behavior: 'instant'});
  }
  function emptyState(title, description, createButton = false) {
    const wrap = node('div', 'empty-state'); wrap.append(node('span', 'empty-icon', '▤'), node('h3', '', title), node('p', '', description));
    if (createButton) { const button = node('button', 'button primary', '＋ 创建第一个任务'); button.type = 'button'; button.addEventListener('click', () => changeView('create')); wrap.append(button); }
    return wrap;
  }
  function renderTaskTable(container, tasks, emptyTitle, emptyDescription) {
    container.replaceChildren();
    if (!tasks.length) { container.append(emptyState(emptyTitle, emptyDescription, state.filter === 'all')); return; }
    const table = node('table', 'task-table');
    const head = node('thead'); const heading = node('tr');
    ['目标服务器 / 域名', '任务类型', '面板版本', '状态', '创建时间', '操作'].forEach((text, index) => { const th = node('th', '', text); th.scope = 'col'; if (index === 0) th.style.width = '27%'; if (index === 5) th.style.width = '10%'; heading.append(th); });
    head.append(heading); const body = node('tbody');
    tasks.forEach(task => {
      const row = node('tr'); const identity = node('td');
      const domain = node('span', 'task-domain', task.domain || '未提供域名'); domain.title = task.domain || ''; identity.append(domain, node('span', 'task-ip', task.server_ip || '—'));
      const kind = node('td'); const kindSpan = node('span', 'task-kind'); kindSpan.append(node('span', 'task-kind-icon', task.kind === 'migrate' ? '⇄' : '＋'), document.createTextNode(taskKind(task))); kind.append(kindSpan);
      const status = node('td'); status.append(badge(task.status));
      const time = node('td'); time.append(node('span', 'task-time', dateTime(task.created_at, true)));
      const action = node('td'); const button = node('button', 'table-action', '查看详情 →'); button.type = 'button'; button.addEventListener('click', () => openTask(task.id)); action.append(button);
      row.append(identity, kind, node('td', '', task.version || '—'), status, time, action); body.append(row);
    });
    table.append(head, body); container.append(table);
  }
  function renderTasks() {
    const tasks = state.tasks;
    setText('#stat-total', tasks.length); setText('#nav-task-count', tasks.length);
    setText('#stat-running', tasks.filter(isActive).length);
    setText('#stat-success', tasks.filter(task => statusType(task.status) === 'success').length);
    setText('#stat-failed', tasks.filter(task => statusType(task.status) === 'failed').length);
    renderTaskTable($('#recent-tasks'), tasks.slice(0, 5), '还没有部署任务', '从全新部署或数据迁移开始，创建你的第一个任务。');
    const visible = tasks.filter(task => state.filter === 'all' || state.filter === 'running' && isActive(task) || state.filter === 'succeeded' && statusType(task.status) === 'success' || state.filter === 'failed' && statusType(task.status) === 'failed');
    renderTaskTable($('#history-tasks'), visible, state.filter === 'all' ? '还没有任务记录' : '没有符合条件的任务', state.filter === 'all' ? '创建任务后，可以在这里跟进执行进度。' : '切换其他筛选条件查看任务。');
  }
  async function loadTasks(manual = false) {
    clearTimeout(state.listTimer); if (!state.user) return;
    const session = state.session; const sequence = ++state.listSequence;
    try {
      const data = await api('/api/tasks');
      if (session !== state.session || sequence !== state.listSequence) return;
      state.tasks = Array.isArray(data.tasks) ? data.tasks : [];
      state.tasks.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
      renderTasks(); $('#global-error').hidden = true;
      if (manual) toast('任务状态已更新');
    } catch (error) {
      if (session !== state.session || sequence !== state.listSequence) return;
      setText('#global-error-text', error.message); $('#global-error').hidden = false;
      if (!state.tasks.length) { $('#recent-tasks').replaceChildren(emptyState('暂时无法加载任务', '连接恢复后将自动更新，也可点击上方重新加载。')); $('#history-tasks').replaceChildren(emptyState('任务加载失败', '请检查服务连接后重试。')); }
    } finally {
      if (state.user && session === state.session && sequence === state.listSequence) state.listTimer = setTimeout(loadTasks, document.hidden ? 20000 : 8000);
    }
  }

  function updateTaskForm() {
    const migration = $('input[name="kind"]:checked').value === 'migrate';
    const customPort = $('#custom-panel-port').checked;
    const portInput = $('#panel-port');
    $('#panel-port-field').hidden = !customPort; portInput.disabled = !customPort; portInput.required = customPort;
    $('#custom-panel-port').setAttribute('aria-expanded', String(customPort));
    setText('#custom-port-label', migration ? '自定义临时安装端口' : '自定义面板端口');
    setText('#panel-port-label', migration ? '自定义临时安装端口' : '自定义面板端口');
    setText('#port-mode-help', migration ? '默认临时随机端口；迁移后沿用数据库原端口。' : '系统随机分配端口，执行时检查是否可用。');
    setText('#panel-port-help', migration ? '这里只设置临时安装端口；导入数据库后会替换为旧面板原端口，请放行旧端口。' : '端口不能与 SSH 或证书验证端口 80 相同，请确保所选端口可用并已放行。');
    setText('#credential-note-title', migration ? '沿用旧面板登录配置' : '默认面板登录信息');
    $('#credential-note-values').hidden = migration;
    setText('#credential-note-help', migration ? '保留原账号密码、原入口路径、原端口、双重验证和节点；请使用原账号及原验证器登录。' : '新部署使用以上登录信息；交付地址包含实际访问路径。');
    $$('.kind-option').forEach(option => option.classList.toggle('selected', $('input', option).checked));
    $('#migration-section').hidden = !migration; $('#source-version').required = migration; $('#database-file').required = migration;
    setText('#summary-title', migration ? '数据迁移' : '全新部署');
    setText('#summary-version', $('#version').value); setText('#summary-server', $('#server-ip').value.trim() || '待填写');
    setText('#summary-domain', $('#domain').value.trim() || '待填写');
    setText('#summary-port-label', migration ? '迁移端口' : '面板端口');
    setText('#summary-port', migration ? customPort ? `临时 ${portInput.value || '待填写'}；最终沿用原端口` : '临时随机端口，最终沿用数据库原端口' : customPort ? portInput.value || '自定义（待填写）' : '系统随机分配');
    $('#summary-migration-item').hidden = !migration;
    setText('#submit-task', migration ? '创建迁移任务 →' : '创建部署任务 →');
    $('#migration-version-warning').hidden = !(migration && $('#source-version').value && $('#source-version').value !== $('#version').value);
    applySubmissionState();
  }
  function showFile() {
    const file = $('#database-file').files[0];
    setText('#file-label', file ? file.name : '点击选择或拖入 x-ui.db');
    setText('#file-description', file ? `${(file.size / 1024 / 1024).toFixed(2)} MiB · 提交后将检查数据库完整性与版本兼容性` : '完整 SQLite 数据库 · 最大 50 MiB');
  }
  async function submitTask(event) {
    event.preventDefault(); const form = event.currentTarget; showError('#task-form-error', '');
    if (executionBlocked()) { showError('#task-form-error', executionMessage()); applySubmissionState(); return; }
    const migration = $('input[name="kind"]:checked').value === 'migrate';
    const domain = $('#domain').value.trim().toLowerCase().replace(/\.$/, '');
    if (!domain || /[\s/:?#@]/.test(domain) || !domain.includes('.')) { showError('#task-form-error', '请填写完整域名，例如 panel.example.com，不含协议、端口或路径。'); return; }
    if (migration && $('#source-version').value !== $('#version').value) { showError('#task-form-error', '第一版支持同版本迁移，请将源版本和目标版本设置为一致。'); return; }
    const file = $('#database-file').files[0];
    if (migration && (!file || file.size === 0 || !file.name.toLowerCase().endsWith('.db'))) { showError('#task-form-error', '请选择有效的 .db 数据库文件，文件不能为空。'); return; }
    if (migration && file.size > 50 * 1024 * 1024) { showError('#task-form-error', '数据库文件不能超过 50 MiB。'); return; }
    const customPort = $('#custom-panel-port').checked;
    const port = Number($('#panel-port').value);
    if (customPort && (!Number.isInteger(port) || port < 1 || port > 65535)) { showError('#task-form-error', '请输入 1–65535 之间的有效端口。'); return; }
    if (customPort && [22, 80, Number($('#ssh-port').value)].includes(port)) { showError('#task-form-error', '自定义端口不能与 SSH 端口或证书验证端口 80 相同。'); return; }
    const data = new FormData();
    data.set('kind', migration ? 'migrate' : 'install'); data.set('server_ip', $('#server-ip').value.trim());
    data.set('ssh_port', $('#ssh-port').value); data.set('ssh_username', 'root'); data.set('ssh_password', $('#ssh-password').value);
    data.set('version', $('#version').value); data.set('domain', domain); data.set('custom_panel_port', String(customPort));
    if (customPort) data.set('panel_port', String(port));
    data.set('overwrite_existing', String($('#overwrite-existing').checked));
    if (migration) { data.set('source_version', $('#source-version').value); data.set('database', file, file.name); }
    setBusy(form, true, '正在提交任务…');
    try {
      const response = await api('/api/tasks', {method: 'POST', body: data});
      if (!response.task || response.task.id == null) throw new Error('服务未返回任务编号，请刷新任务历史确认提交结果。');
      $('#ssh-password').value = ''; $('#database-file').value = ''; showFile();
      toast('任务已提交，可在详情中查看实际执行进度'); await openTask(response.task.id); loadTasks();
    } catch (error) { showError('#task-form-error', error.message); }
    finally { setBusy(form, false); updateTaskForm(); }
  }

  function infoPair(list, label, value) { const wrap = node('div'); wrap.append(node('dt', '', label), node('dd', '', value == null || value === '' ? '—' : value)); list.append(wrap); }
  function safePanelURL(value) {
    if (typeof value !== 'string') return null;
    try { const url = new URL(value); return url.protocol === 'https:' && !url.username && !url.password ? url.href : null; } catch { return null; }
  }
  function checkDescription(value, kind) {
    if (value == null) return {text: `${kind}：未返回检查结果`, className: 'unknown'};
    if (typeof value === 'boolean') return {text: `${kind}：${value ? '检查通过' : '检查未通过'}`, className: value ? '' : 'warning'};
    if (typeof value === 'string') return {text: `${kind}：${value}`, className: /^(ok|enabled|active|valid|verified|success|succeeded)$/i.test(value) ? '' : 'unknown'};
    const status = value.status || value.enabled === true && '已开启' || value.ok === true && '检查通过' || value.valid === true && '有效';
    const text = value.message || value.detail || status || '已返回检查信息';
    const warning = value.enabled === false || value.ok === false || value.valid === false || /fail|error|unsupported|warning|disabled/i.test(String(value.status || ''));
    return {text: `${kind}：${text}`, className: warning ? 'warning' : ''};
  }
  function renderResult(task) {
    const completed = statusType(task.status) === 'success';
    $('#result-panel').hidden = !completed;
    if (!completed) return;
    const result = task.result && typeof task.result === 'object' ? task.result : {};
    const preserved = result.credentials_preserved === true;
    const scheduledReboot = task.kind === 'migrate' && typeof result.reboot_scheduled === 'boolean';
    const url = safePanelURL(result.panel_url || result.url || result.access_url);
    setText('#result-title', task.kind === 'migrate' ? '迁移已完成' : '部署已完成');
    setText('#result-description', scheduledReboot ? result.reboot_scheduled ? '迁移完成，已安排服务器重启；重启期间面板暂不可访问，请稍后打开。' : '迁移完成，但自动重启未确认，请手动重启。' : preserved ? result.panel_access_verified === true ? 'HTTPS / 服务已验证；请使用原账号及原验证器登录。' : '已沿用旧面板登录配置；请使用原账号及原验证器登录。' : '以下为本次任务返回的实际交付信息。');
    const anchor = $('#result-url');
    if (url) { anchor.href = url; anchor.textContent = url; anchor.removeAttribute('aria-disabled'); }
    else { anchor.removeAttribute('href'); anchor.textContent = '服务端未返回有效 HTTPS 地址，请查看执行日志。'; anchor.setAttribute('aria-disabled', 'true'); }
    $('#copy-url').disabled = !url;
    setText('#result-username', preserved ? '沿用原面板账号' : result.username || result.panel_username || '未返回');
    setText('#result-password', preserved ? '沿用原面板密码' : result.password || result.panel_password || '未返回');
    const checks = $('#result-checks'); checks.replaceChildren();
    const entries = [[result.certificate ?? result.ssl ?? result.certificate_status, 'SSL'], [result.bbr ?? result.bbr_enabled ?? result.bbr_status, 'BBR']];
    entries.forEach(([value, kind]) => { const check = checkDescription(value, kind); const pill = node('span', `check-pill ${check.className}`, check.text); if (value && typeof value === 'object' && value.expires_at) pill.title = `到期时间：${dateTime(value.expires_at)}`; checks.append(pill); });
    const metadata = $('#result-meta'); metadata.replaceChildren();
    if (scheduledReboot) {
      const verification = node('div', `notice ${result.reboot_scheduled ? 'info' : 'warning'}`, `HTTPS、服务与数据库检查在安排重启前完成，未等待服务器重启后恢复。${preserved ? '请使用原账号、原密码及原验证器登录。' : ''}`);
      verification.style.marginTop = '16px'; verification.style.marginBottom = '0'; metadata.append(verification);
    }
    if (result.panel_port != null) {
      const delivered = node('div', 'result-delivery-settings');
      delivered.append(node('span', '', '实际面板端口'), node('code', '', result.panel_port)); metadata.append(delivered);
    }
    if (typeof result.backup_path === 'string' && result.backup_path) {
      const backup = node('div', 'result-backup'); const path = node('code', 'backup-path', result.backup_path);
      const copy = node('button', 'text-button', '复制目录'); copy.type = 'button';
      copy.addEventListener('click', async () => {
        try { await navigator.clipboard.writeText(result.backup_path); toast('备份目录已复制'); }
        catch { const selection = window.getSelection(); const range = document.createRange(); range.selectNodeContents(path); selection.removeAllRanges(); selection.addRange(range); toast('已选中备份目录，请手动复制。'); }
      });
      const heading = node('div', 'backup-heading'); heading.append(node('span', '', '服务器备份目录'), copy);
      backup.append(heading, path); metadata.append(backup);
    }
    if (task.kind === 'migrate') {
      const stats = result.migration_counts || result.migration_stats || result.migration || result.stats || result;
      if (stats && typeof stats === 'object' && !Array.isArray(stats)) {
        const counts = [[stats.inbounds ?? stats.inbound_count, '入站配置'], [stats.clients ?? stats.client_count, stats.client_count_kind || '客户条目']];
        const items = counts.filter(([value]) => typeof value === 'number' && Number.isFinite(value) && value >= 0);
        if (items.length) {
          const summary = node('div', 'migration-statistics');
          items.forEach(([value, label]) => { const item = node('span'); item.append(node('strong', '', value), document.createTextNode(` ${label}`)); summary.append(item); });
          metadata.append(summary);
        }
      }
    }
    const warnings = $('#result-warnings'); warnings.replaceChildren();
    const values = result.warnings || task.warnings || [];
    (Array.isArray(values) ? values : [values]).filter(Boolean).forEach(value => warnings.append(node('div', 'notice warning', errorMessage(value))));
  }
  function renderStages(task, events) {
    const list = $('#task-stages'); list.replaceChildren();
    const stages = [];
    events.forEach(event => { if (event.stage && !stages.includes(event.stage)) stages.push(event.stage); });
    if (task.stage && !stages.includes(task.stage)) stages.push(task.stage);
    if (!stages.length) stages.push(task.status === 'queued' ? 'queued' : 'starting');
    const type = statusType(task.status);
    const failedStage = type === 'failed' ? [...events].reverse().find(event => event.stage && !['queued', 'starting', 'rollback', 'failed', 'interrupted', 'completed'].includes(event.stage))?.stage : null;
    const currentIndex = Math.max(0, stages.indexOf(task.stage));
    stages.forEach((stage, index) => {
      const current = stage === task.stage || !task.stage && index === stages.length - 1;
      const failed = type === 'failed' && (current || stage === failedStage || stage === 'rollback' && /回滚未完成|恢复未完成/.test(task.error || ''));
      const done = !failed && (type === 'success' || !current && index < currentIndex);
      const item = node('li', failed ? 'failed' : done ? 'done' : current ? 'current' : '');
      item.append(node('span', 'stage-dot', failed ? '!' : done ? '✓' : index + 1));
      const label = node('span', 'stage-text', stage === 'reboot' && task.kind === 'migrate' && typeof task.result?.reboot_scheduled === 'boolean' ? '安排服务器重启' : stageLabel(stage));
      if (current || failed) label.append(node('small', '', failed ? '此阶段发生错误' : type === 'success' ? '已完成' : '当前阶段'));
      item.append(label); list.append(item);
    });
  }
  function renderLogs(events, task) {
    const target = $('#task-logs');
    const nearBottom = target.scrollHeight - target.scrollTop - target.clientHeight < 80;
    const signature = JSON.stringify([events.length, events[events.length - 1]?.id, events[events.length - 1]?.message, task.status]);
    if (target.dataset.signature === signature) return;
    target.dataset.signature = signature; target.replaceChildren();
    if (!events.length) { target.append(node('p', 'logs-placeholder', statusType(task.status) === 'queued' ? '任务已创建，正在等待执行器处理。' : '暂无执行日志。')); return; }
    events.forEach(event => {
      const line = node('div', 'log-line'); line.append(node('time', 'log-time', logTime(event.created_at)), node('span', 'log-message', event.message || stageLabel(event.stage))); target.append(line);
    });
    if (nearBottom) target.scrollTop = target.scrollHeight;
  }
  function renderQueueInfo(task) {
    const target = $('#queue-notice'); target.replaceChildren();
    target.hidden = !['queued', 'pending'].includes(task.status);
    if (target.hidden) return;
    const info = task.queue_info && typeof task.queue_info === 'object' ? task.queue_info : {};
    const content = node('div');
    content.append(node('strong', '', info.message || (executionBlocked() ? executionMessage() : '任务正在排队，等待执行器处理。')));
    const details = [];
    if (Number.isInteger(info.position) && info.position >= 1) details.push(`队列位置：第 ${info.position} 位`);
    if (Number.isInteger(info.active_jobs) && Number.isInteger(info.capacity)) details.push(`正在执行：${info.active_jobs} / ${info.capacity}`);
    if (Number.isFinite(info.wait_seconds) && info.wait_seconds >= 0) {
      const seconds = Math.floor(info.wait_seconds); const minutes = Math.floor(seconds / 60);
      details.push(`已等待：${minutes ? `${minutes} 分 ` : ''}${seconds % 60} 秒`);
    }
    if (details.length) content.append(node('p', '', details.join(' · ')));
    if (executionBlocked() && info.message && info.message !== executionMessage()) content.append(node('p', '', executionMessage()));
    target.append(node('span', '', '◷'), content);
  }
  function hasHostKeyChange(task) {
    const code = String(task?.error_code || '').toLowerCase();
    return task?.status === 'failed' && (['ssh_host_key_changed', 'host_key_changed'].includes(code) || /SSH\s*指纹已变化/.test(task.error ? errorMessage(task.error) : ''));
  }
  function renderDetail(task, events) {
    state.task = task; state.events = events;
    setText('#detail-title', taskKind(task)); setText('#detail-subtitle', `${task.domain || task.server_ip || '目标服务器'} · ${dateTime(task.created_at)}`);
    const status = $('#detail-status'); status.className = `badge ${statusType(task.status)}`; status.textContent = statusLabel(task.status);
    const info = $('#detail-info'); info.replaceChildren();
    infoPair(info, '任务编号', task.id); infoPair(info, '任务类型', taskKind(task)); infoPair(info, '服务器', task.server_ip);
    infoPair(info, '目标版本', task.version); if (task.source_version) infoPair(info, '源版本', task.source_version);
    infoPair(info, '绑定域名', task.domain);
    if (task.kind === 'migrate') {
      infoPair(info, '临时安装端口', task.panel_port);
      const restoredPort = task.result?.panel_port ?? task.validation?.panel_settings?.port;
      if (restoredPort != null) infoPair(info, '迁移后面板端口', restoredPort);
    } else infoPair(info, '面板端口', task.result?.panel_port ?? task.panel_port);
    infoPair(info, '当前阶段', stageLabel(task.stage)); infoPair(info, '创建时间', dateTime(task.created_at));
    if (task.finished_at || task.completed_at) infoPair(info, '结束时间', dateTime(task.finished_at || task.completed_at));
    $('#task-error-panel').hidden = statusType(task.status) !== 'failed';
    let detailError = task.error ? errorMessage(task.error) : '任务未完成，请根据执行日志检查后重试。';
    if (hasHostKeyChange(task)) detailError = '该任务使用旧规则拒绝了变化的 SSH 指纹。现在重试会自动更新指纹并继续，请填写 SSH 密码重试。';
    setText('#detail-error', detailError);
    $('#retry-panel').hidden = !['failed', 'interrupted'].includes(task.status);
    setText('#retry-target-summary', `重试沿用此任务的域名 ${task.domain || '未提供'} 和服务器 IP ${task.server_ip || '未提供'}；如需更换，请新建任务。`);
    $('#log-live').hidden = !isActive(task);
    renderResult(task); renderStages(task, events); renderLogs(events, task); renderQueueInfo(task);
  }
  async function openTask(id) {
    changeView('detail'); state.taskId = String(id); state.task = null;
    setText('#detail-title', '任务详情'); setText('#detail-subtitle', '正在加载任务信息…');
    const status = $('#detail-status'); status.className = 'badge'; status.textContent = '读取中';
    $('#result-panel').hidden = true; $('#task-error-panel').hidden = true; $('#retry-panel').hidden = true; $('#log-live').hidden = true;
    $('#queue-notice').hidden = true;
    $('#task-logs').replaceChildren(node('p', 'logs-placeholder', '正在读取日志…')); $('#task-logs').dataset.signature = '';
    $('#detail-info').replaceChildren(); $('#task-stages').replaceChildren(); showError('#retry-error', '');
    $('#retry-password').value = '';
    await pollTask();
  }
  async function pollTask() {
    clearTimeout(state.detailTimer); if (!state.user || state.view !== 'detail' || !state.taskId) return;
    const id = state.taskId; const session = state.session;
    let keepPolling = true;
    try {
      const data = await api(`/api/tasks/${encodeURIComponent(id)}`);
      if (session !== state.session || state.taskId !== id) return;
      if (!data.task) throw new Error('服务未返回任务详情，请稍后重试。');
      renderDetail(data.task, Array.isArray(data.events) ? data.events : []); keepPolling = isActive(data.task);
      $('#global-error').hidden = true;
      const index = state.tasks.findIndex(task => String(task.id) === id);
      if (index >= 0) state.tasks[index] = data.task; else state.tasks.unshift(data.task);
      renderTasks();
    } catch (error) {
      if (session !== state.session || state.taskId !== id) return;
      setText('#global-error-text', error.message); $('#global-error').hidden = false;
      if (!state.task) { setText('#detail-subtitle', '暂时无法加载详情，正在等待重试。'); $('#task-logs').replaceChildren(node('p', 'logs-placeholder', '日志读取失败，连接恢复后会自动重试。')); }
    } finally {
      if (keepPolling && state.user && session === state.session && state.taskId === id && state.view === 'detail') state.detailTimer = setTimeout(pollTask, document.hidden ? 15000 : 3000);
    }
  }

  async function loadUsers() {
    if (!state.user || state.user.role !== 'admin') return;
    const session = state.session;
    try {
      const data = await api('/api/admin/users'); if (session !== state.session) return;
      const users = Array.isArray(data.users) ? data.users : []; const target = $('#users-list'); target.replaceChildren();
      if (!users.length) { target.append(emptyState('还没有客户账号', '在右侧创建第一个客户账号。')); return; }
      const table = node('table', 'task-table'); const head = node('thead'); const row = node('tr');
      ['用户名', '状态', '创建时间', '操作'].forEach(text => { const th = node('th', '', text); th.scope = 'col'; row.append(th); }); head.append(row);
      const body = node('tbody');
      users.forEach(user => {
        const tr = node('tr'); const name = node('td'); name.append(node('span', 'user-row-name', user.username)); if (user.role === 'admin') name.append(node('div', 'role-chip', '管理员'));
        const active = user.active !== undefined ? user.active : user.is_active !== false; const status = node('td'); status.append(node('span', `badge ${active ? 'success' : 'failed'}`, active ? '已启用' : '已停用'));
        const action = node('td', 'user-row-actions');
        if (String(user.id) === String(state.user.id) || user.role === 'admin') action.append(node('span', 'role-chip', String(user.id) === String(state.user.id) ? '当前账号' : '管理员'));
        else { const button = node('button', `user-action ${active ? '' : 'enable'}`, active ? '停用' : '启用'); button.type = 'button'; button.addEventListener('click', async () => { button.disabled = true; try { await api(`/api/admin/users/${encodeURIComponent(user.id)}`, {method: 'PATCH', body: {active: !active}}); toast(active ? '账号已停用' : '账号已启用'); await loadUsers(); } catch (error) { toast(error.message); button.disabled = false; } }); action.append(button); }
        if (user.role !== 'admin') { const assign = node('button', 'text-button user-domain-button', '分配域名'); assign.type = 'button'; assign.addEventListener('click', () => openDomainAccess(user, assign)); action.append(assign); }
        tr.append(name, status, node('td', 'task-time', dateTime(user.created_at, true)), action); body.append(tr);
      });
      table.append(head, body); target.append(table);
    } catch (error) { if (session === state.session) $('#users-list').replaceChildren(emptyState('无法加载客户列表', error.message)); }
  }

  function closeDomainAccess(force = false) {
    if (domainAccess.saving && !force) return;
    if (force) domainAccess.saving = false;
    domainAccess.sequence += 1; domainAccess.user = null; domainAccess.zones = []; domainAccess.selected = new Set();
    $('#domain-access-overlay').hidden = true; $('#domain-access-form').reset(); setBusy($('#domain-access-form'), false); $('#domain-access-zones').replaceChildren();
    document.body.classList.remove('modal-open'); showError('#domain-access-error', '');
    setText('#domain-access-user', ''); setText('#domain-access-count', '');
    if (domainAccess.focusReturn?.isConnected) domainAccess.focusReturn.focus(); domainAccess.focusReturn = null;
  }
  function renderDomainAccess() {
    const target = $('#domain-access-zones'); const search = $('#domain-access-search').value.trim().toLowerCase(); target.replaceChildren();
    const zones = domainAccess.zones.filter(zone => zone.name.toLowerCase().includes(search));
    setText('#domain-access-count', `已选择 ${domainAccess.selected.size} 个域名`);
    if (!zones.length) { dnsEmpty(target, search ? '没有匹配的域名' : '没有可分配域名', search ? '换个关键词试试。' : '请先在“域名与 DNS”连接 Cloudflare 并检查域名权限。'); return; }
    zones.forEach(zone => {
      const label = node('label', 'domain-access-option'); const checkbox = node('input'); checkbox.type = 'checkbox'; checkbox.checked = domainAccess.selected.has(zone.id); checkbox.value = zone.id;
      checkbox.addEventListener('change', () => { if (checkbox.checked) domainAccess.selected.add(zone.id); else domainAccess.selected.delete(zone.id); setText('#domain-access-count', `已选择 ${domainAccess.selected.size} 个域名`); });
      const text = node('span'); text.append(node('strong', '', zone.name), node('small', '', zone.status === 'active' ? '已激活' : zone.status === 'pending' ? '等待激活' : zone.status || '状态未返回'));
      label.append(checkbox, text); target.append(label);
    });
  }
  async function openDomainAccess(user, trigger = null) {
    if (state.user?.role !== 'admin' || user.role === 'admin') return;
    closeDomainAccess(true); domainAccess.user = user; domainAccess.focusReturn = trigger || document.activeElement;
    const session = state.session; const sequence = ++domainAccess.sequence;
    setText('#domain-access-user', `客户：${user.username}`); setText('#domain-access-count', '正在读取授权…');
    $('#domain-access-overlay').hidden = false; document.body.classList.add('modal-open'); $('#domain-access-save').disabled = true;
    dnsEmpty($('#domain-access-zones'), '正在读取可分配域名…', '', true); $('#domain-access-dialog').focus();
    try {
      const data = await api(`/api/admin/users/${encodeURIComponent(user.id)}/domains`);
      if (session !== state.session || sequence !== domainAccess.sequence) return;
      domainAccess.zones = Array.isArray(data.zones) ? data.zones : [];
      const assigned = new Set(Array.isArray(data.assigned_zone_ids) ? data.assigned_zone_ids : []);
      domainAccess.selected = new Set(domainAccess.zones.filter(zone => assigned.has(zone.id)).map(zone => zone.id));
      setText('#domain-access-limit', `客户只能操作选中的域名，每个域名最多 ${data.record_limit || 100} 条记录。未选择表示不授权任何域名。`);
      renderDomainAccess(); $('#domain-access-save').disabled = false;
    } catch (error) { if (session === state.session && sequence === domainAccess.sequence) { showError('#domain-access-error', error.message); dnsEmpty($('#domain-access-zones'), '无法读取域名授权', '关闭后重新打开，或检查 Cloudflare 配置。'); } }
  }
  async function saveDomainAccess(event) {
    event.preventDefault(); if (state.user?.role !== 'admin' || !domainAccess.user || domainAccess.saving || $('#domain-access-save').disabled) return;
    const session = state.session; const sequence = domainAccess.sequence; const user = domainAccess.user; const form = event.currentTarget;
    const zoneIds = domainAccess.zones.filter(zone => domainAccess.selected.has(zone.id)).map(zone => zone.id);
    domainAccess.saving = true; setBusy(form, true, '正在保存…'); showError('#domain-access-error', '');
    try {
      await api(`/api/admin/users/${encodeURIComponent(user.id)}/domains`, {method: 'PUT', body: {zone_ids: zoneIds}});
      if (session !== state.session || sequence !== domainAccess.sequence) return;
      domainAccess.saving = false; closeDomainAccess(); toast(`已更新 ${user.username} 的域名授权`);
    } catch (error) { if (session === state.session && sequence === domainAccess.sequence) showError('#domain-access-error', error.message); }
    finally { if (session === state.session && sequence === domainAccess.sequence) { domainAccess.saving = false; setBusy(form, false); } }
  }

  function cfStatus(label, tone = 'queued') {
    const target = $('#cf-status'); target.className = `badge ${tone}`; target.textContent = label;
  }
  function resetCloudflare() {
    cf.configSequence += 1; cf.recordSequence += 1;
    cf.configuration = null; cf.zones = []; cf.records = []; cf.zone = null; cf.recordLimit = 100; cf.recordSaving = false;
    domainAccess.saving = false; closeDomainAccess(true); closeDNSEditor(true); $('#cf-config-form').reset(); setBusy($('#cf-config-form'), false); $('#cf-zone-search').value = '';
    $('#cf-zones').replaceChildren(); $('#cf-records').replaceChildren();
    $('#cloudflare-nav').hidden = true; $('#cloudflare-view').hidden = true; $('#cf-admin-config').hidden = true;
    ['#cf-page-error', '#cf-config-error', '#cf-records-error'].forEach(selector => showError(selector, ''));
    setText('#cf-zone-count', '0'); setText('#cf-zone-title', '选择一个域名'); setText('#cf-records-summary', '解析记录会显示在这里。');
    setText('#dns-editor-zone', ''); setText('#dns-name-suffix', ''); setText('#dns-name-preview', ''); $('#dns-readonly-values').replaceChildren(); setRecordControls(false);
  }
  function renderCFConfiguration(configuration) {
    cf.configuration = configuration;
    $('#cf-account-id').value = configuration.account_id || '';
    const configured = configuration.configured === true;
    $('#cf-api-token').required = !configured; $('#cf-token-required').hidden = configured;
    $('#cf-api-token').placeholder = configured ? '留空保留已保存的 Token' : '输入 API Token';
    setText('#cf-token-help', configured ? '已保存 Token，不会回显。留空保留，填写新值则替换。' : '需要该账号的 Zone:Read 和 DNS:Edit 权限。');
    setText('#cf-config-summary', configured ? `已保存账号配置${configuration.updated_at ? ` · 更新于 ${dateTime(configuration.updated_at)}` : ''}` : '配置账号与 API Token 后读取域名。');
    cfStatus(configured ? '已配置，待连接' : '尚未配置');
  }
  function dnsEmpty(target, title, message, loading = false) {
    const wrap = node('div', 'dns-empty');
    wrap.append(node('span', loading ? 'spinner' : '', loading ? '' : '◎'), node('strong', '', title));
    if (message) wrap.append(node('p', '', message));
    target.replaceChildren(wrap);
  }
  function renderCFZones() {
    const target = $('#cf-zones'); const search = $('#cf-zone-search').value.trim().toLowerCase();
    const zones = cf.zones.filter(zone => String(zone.name || '').toLowerCase().includes(search));
    setText('#cf-zone-count', cf.zones.length); target.replaceChildren();
    if (!zones.length) { dnsEmpty(target, search ? '没有匹配的域名' : state.user?.role === 'admin' ? '没有可用域名' : '尚未分配域名', search ? '换个关键词试试。' : state.user?.role === 'admin' ? '检查 Cloudflare 账号下的域名及 Token 权限。' : '请联系管理员为你的账号分配可操作域名。'); return; }
    zones.forEach(zone => {
      const button = node('button', `dns-zone-item ${cf.zone?.id === zone.id ? 'selected' : ''}`); button.type = 'button';
      const text = node('span'); text.append(node('strong', '', zone.name), node('small', '', zone.status === 'active' ? '已激活' : zone.status === 'pending' ? '等待激活' : zone.status || '状态未返回'));
      button.append(node('span', 'dns-zone-symbol', '◎'), text, node('span', 'dns-zone-arrow', '›'));
      button.setAttribute('aria-pressed', String(cf.zone?.id === zone.id));
      button.addEventListener('click', () => loadCFRecords(zone)); target.append(button);
    });
  }
  function setRecordControls(available) {
    const atLimit = available && cf.records.length >= cf.recordLimit;
    $('#cf-add-record').disabled = !available || atLimit; $('#cf-records-refresh').disabled = !available;
    $('#cf-add-record').title = atLimit ? `已达到每个域名 ${cf.recordLimit} 条记录上限，请先删除不需要的记录。` : '';
    const message = $('#cf-record-limit'); message.hidden = !atLimit;
    message.textContent = atLimit ? `已达到每个域名 ${cf.recordLimit} 条记录上限，暂时不能新增。已有记录仍可编辑或删除。` : '';
  }
  async function loadCloudflare() {
    if (!state.user) return;
    const session = state.session; const sequence = ++cf.configSequence;
    cf.recordSequence += 1;
    cfStatus('读取配置…', 'running'); $('#cf-refresh').disabled = true; setRecordControls(false); showError('#cf-config-error', ''); showError('#cf-page-error', ''); showError('#cf-records-error', '');
    try {
      if (state.user.role === 'admin') {
        const data = await api('/api/admin/cloudflare');
        if (session !== state.session || sequence !== cf.configSequence) return;
        renderCFConfiguration(data);
        if (!data.configured) {
          cf.zones = []; cf.records = []; cf.zone = null;
          setText('#cf-zone-count', '0'); setRecordControls(false);
          dnsEmpty($('#cf-zones'), '等待连接 Cloudflare', '保存账号配置后读取域名。');
          dnsEmpty($('#cf-records'), '尚未选择域名', '请先填写账号配置并保存验证。');
          return;
        }
      }
      await loadCFZones(session, sequence);
    } catch (error) {
      if (session !== state.session || sequence !== cf.configSequence) return;
      cfStatus('连接失败', 'failed'); showError('#cf-page-error', error.message);
      cf.zones = []; cf.records = []; cf.zone = null; renderCFZones();
      dnsEmpty($('#cf-records'), '暂时无法加载域名', '请刷新重试，或联系管理员检查域名授权与连接配置。');
    } finally { if (session === state.session && sequence === cf.configSequence) $('#cf-refresh').disabled = false; }
  }
  async function loadCFZones(session = state.session, sequence = cf.configSequence) {
    cfStatus('连接 Cloudflare…', 'running'); dnsEmpty($('#cf-zones'), '正在读取域名…', '', true);
    const data = await api('/api/dns/zones');
    if (session !== state.session || sequence !== cf.configSequence) return;
    cf.recordLimit = Number.isInteger(data.record_limit) && data.record_limit > 0 ? data.record_limit : 100;
    cf.zones = Array.isArray(data.zones) ? data.zones : []; cfStatus('已连接', 'success');
    const selected = cf.zones.find(zone => zone.id === cf.zone?.id) || cf.zones[0];
    renderCFZones();
    if (selected) await loadCFRecords(selected);
    else { cf.zone = null; cf.records = []; cf.recordSequence += 1; setRecordControls(false); setText('#cf-zone-title', '选择一个域名'); setText('#cf-records-summary', '解析记录会显示在这里。'); dnsEmpty($('#cf-records'), state.user?.role === 'admin' ? '没有可管理的域名' : '尚未分配域名', state.user?.role === 'admin' ? '检查 Cloudflare 账号及 Token 的域名读取权限。' : '你的账号暂未获得域名权限，请联系管理员分配。'); }
  }
  async function saveCFConfiguration(event) {
    event.preventDefault(); if (state.user?.role !== 'admin') return;
    const form = event.currentTarget; const session = state.session; const sequence = ++cf.configSequence;
    const body = {account_id: $('#cf-account-id').value.trim()};
    const token = $('#cf-api-token').value.trim(); if (token) body.api_token = token;
    if (!body.api_token && cf.configuration?.configured !== true) { showError('#cf-config-error', '首次配置需要填写 API Token。'); return; }
    setBusy(form, true, '正在保存并验证…'); cfStatus('正在验证…', 'running'); showError('#cf-config-error', '');
    closeDNSEditor(); cf.zone = null; cf.records = []; cf.recordSequence += 1; setRecordControls(false);
    dnsEmpty($('#cf-records'), '正在验证账号配置…', '', true);
    try {
      const data = await api('/api/admin/cloudflare', {method: 'PUT', body});
      if (session !== state.session || sequence !== cf.configSequence) return;
      if (!data.configuration) throw new Error('服务未返回配置结果，请刷新状态确认。');
      $('#cf-api-token').value = ''; renderCFConfiguration(data.configuration); cfStatus('已连接', 'success');
      cf.zone = null; cf.records = []; cf.recordSequence += 1;
      toast('Cloudflare 配置已保存并验证'); await loadCFZones(session, sequence);
    } catch (error) {
      if (session !== state.session || sequence !== cf.configSequence) return;
      cfStatus('验证失败', 'failed'); showError('#cf-config-error', error.message);
    } finally { if (session === state.session) setBusy(form, false); }
  }
  function cfRecordsPath(zoneId = cf.zone?.id) { return `/api/dns/zones/${encodeURIComponent(zoneId)}/records`; }
  async function loadCFRecords(zone = cf.zone) {
    if (!state.user || !zone) return;
    const session = state.session; const sequence = ++cf.recordSequence;
    cf.zone = zone; cf.records = []; setRecordControls(false); renderCFZones();
    setText('#cf-zone-title', zone.name); setText('#cf-records-summary', '正在读取 DNS 记录…'); showError('#cf-records-error', '');
    dnsEmpty($('#cf-records'), '正在读取解析记录…', '', true);
    try {
      const data = await api(cfRecordsPath(zone.id));
      if (session !== state.session || sequence !== cf.recordSequence) return;
      cf.zone = {...zone, ...(data.zone || {})}; cf.records = Array.isArray(data.records) ? data.records : [];
      cf.recordLimit = Number.isInteger(data.record_limit) && data.record_limit > 0 ? data.record_limit : 100;
      setText('#cf-zone-title', cf.zone.name); setText('#cf-records-summary', `${cf.records.length}/${cf.recordLimit} 条记录 · 修改直接同步到 Cloudflare`);
      renderCFRecords(); setRecordControls(true);
    } catch (error) {
      if (session !== state.session || sequence !== cf.recordSequence) return;
      setText('#cf-records-summary', '读取失败，可点击刷新记录重试。');
      showError('#cf-records-error', error.message); dnsEmpty($('#cf-records'), '暂时无法读取记录', '检查 Cloudflare 配置或稍后重试。');
      $('#cf-records-refresh').disabled = false;
    }
  }
  function renderCFRecords() {
    const target = $('#cf-records'); target.replaceChildren();
    if (!cf.records.length) { dnsEmpty(target, '还没有解析记录', '点击“添加记录”创建第一条 DNS 记录。'); return; }
    const table = node('table', 'dns-table'); const head = node('thead'); const heading = node('tr');
    ['类型', '名称', '内容', 'TTL', '代理状态', '操作'].forEach(value => { const th = node('th', '', value); th.scope = 'col'; heading.append(th); });
    head.append(heading); const body = node('tbody');
    cf.records.forEach(record => {
      const row = node('tr'); const type = node('td'); type.append(node('span', 'dns-type-chip', record.type));
      const name = node('td'); name.append(node('span', 'dns-record-name', record.name));
      if (record.comment) name.append(node('small', 'dns-record-comment', record.comment));
      const content = node('td'); const value = node('code', 'dns-record-content', record.content ?? '—'); value.title = String(record.content ?? ''); content.append(value);
      if (record.type === 'MX') content.append(node('small', 'dns-record-comment', `优先级 ${record.priority ?? '未返回'}`));
      const proxy = node('td'); const proxyBadge = node('span', `dns-proxy-badge ${record.proxied ? 'orange' : 'gray'}`); proxyBadge.append(node('span', 'dns-cloud', '☁'), document.createTextNode(record.proxied ? '已代理' : '仅 DNS')); proxy.append(proxyBadge);
      const actions = node('td', 'dns-row-actions'); const edit = node('button', 'text-button', editableDNSTypes.has(record.type) ? '编辑' : '查看'); edit.type = 'button'; edit.addEventListener('click', () => openDNSEditor(record, edit));
      actions.append(edit);
      if (editableDNSTypes.has(record.type)) { const remove = node('button', 'text-button dns-delete-button', '删除'); remove.type = 'button'; remove.addEventListener('click', () => deleteDNSRecord(record, remove)); actions.append(remove); }
      row.append(type, name, content, node('td', 'dns-ttl-value', record.ttl === 1 ? '自动' : `${record.ttl ?? '—'} 秒`), proxy, actions); body.append(row);
    });
    table.append(head, body); target.append(table);
  }
  function relativeDNSName(name, zoneName = cf.zone?.name || '') {
    const value = String(name || '').trim().replace(/[。．｡]/g, '.').replace(/\.$/, '');
    const zone = zoneName.replace(/\.$/, '');
    if (value.toLowerCase() === zone.toLowerCase()) return '@';
    if (zone && value.toLowerCase().endsWith(`.${zone.toLowerCase()}`)) return value.slice(0, -(zone.length + 1));
    return value;
  }
  function updateDNSNamePreview() {
    const zone = cf.zone?.name || ''; const prefix = relativeDNSName($('#dns-name').value, zone);
    setText('#dns-name-suffix', `.${zone}`);
    setText('#dns-name-preview', prefix ? `完整域名：${prefix === '@' ? zone : `${prefix}.${zone}`}` : '填写前缀后显示完整域名；@ 表示根域名。');
  }
  function updateDNSEditor() {
    const type = $('#dns-type').value; const txt = type === 'TXT'; const mx = type === 'MX'; const proxied = ['A', 'AAAA', 'CNAME'].includes(type);
    $('#dns-txt-field').hidden = !txt; $('#dns-txt-content').disabled = !txt; $('#dns-txt-content').required = txt;
    $('#dns-content-field').hidden = txt; $('#dns-content').disabled = txt; $('#dns-content').required = !txt;
    setText('#dns-content-label', `${type === 'A' ? 'IPv4 地址' : type === 'AAAA' ? 'IPv6 地址' : type === 'MX' ? '邮件服务器' : '目标域名'} *`);
    $('#dns-content').placeholder = type === 'A' ? '203.0.113.10' : type === 'AAAA' ? '2001:db8::10' : type === 'MX' ? 'mail.example.com' : 'target.example.com';
    $('#dns-priority-field').hidden = !mx; $('#dns-priority').disabled = !mx; $('#dns-priority').required = mx;
    $('#dns-proxy-field').hidden = !proxied; $('#dns-proxied').disabled = !proxied;
    if (!proxied) $('#dns-proxied').checked = false;
    const customTTL = $('#dns-ttl-mode').value === 'custom';
    $('#dns-ttl-field').hidden = !customTTL; $('#dns-ttl').disabled = !customTTL; $('#dns-ttl').required = customTTL;
    updateDNSNamePreview();
  }
  function closeDNSEditor(force = false) {
    if (cf.recordSaving && !force) return;
    if (force) cf.recordSaving = false;
    $('#dns-editor-overlay').hidden = true; document.body.classList.remove('modal-open');
    $('#dns-record-form').reset(); setBusy($('#dns-record-form'), false); cf.editorRecord = null; showError('#dns-editor-error', '');
    if (cf.focusReturn?.isConnected) cf.focusReturn.focus(); cf.focusReturn = null;
  }
  function openDNSEditor(record = null, trigger = null) {
    if (!state.user || !cf.zone) return;
    if (!record && cf.records.length >= cf.recordLimit) { toast(`此域名已达到 ${cf.recordLimit} 条记录上限，请先删除不需要的记录。`); return; }
    cf.editorRecord = record; cf.focusReturn = trigger || document.activeElement;
    const readOnly = record && !editableDNSTypes.has(record.type);
    $('#dns-record-form').reset(); showError('#dns-editor-error', '');
    setText('#dns-editor-title', readOnly ? '查看 DNS 记录' : record ? '编辑 DNS 记录' : '添加 DNS 记录');
    setText('#dns-editor-zone', cf.zone.name); $('#dns-readonly-panel').hidden = !readOnly; $('#dns-record-form').hidden = Boolean(readOnly);
    if (readOnly) {
      const list = $('#dns-readonly-values'); list.replaceChildren();
      [['类型', record.type], ['名称', record.name], ['内容', record.content], ['TTL', record.ttl === 1 ? '自动' : `${record.ttl} 秒`], ['代理', record.proxied ? '已代理' : '仅 DNS'], ['备注', record.comment || '—']].forEach(([label, value]) => infoPair(list, label, value));
    } else {
      $('#dns-type').value = record?.type || 'A'; $('#dns-name').value = record ? relativeDNSName(record.name) : ''; $('#dns-name').placeholder = '例如 aaa、foo.bar 或 @';
      $('#dns-content').value = record?.content || ''; $('#dns-txt-content').value = record?.content || '';
      $('#dns-ttl-mode').value = !record || record.ttl === 1 ? 'auto' : 'custom'; $('#dns-ttl').value = record && record.ttl !== 1 ? record.ttl : 300;
      $('#dns-priority').value = record?.priority ?? 10; $('#dns-proxied').checked = record?.proxied === true; $('#dns-comment').value = record?.comment || '';
      const button = $('button[type="submit"]', $('#dns-record-form')); button.textContent = record ? '保存修改' : '添加记录'; updateDNSEditor();
    }
    $('#dns-editor-overlay').hidden = false; document.body.classList.add('modal-open');
    (readOnly ? $('#dns-editor-dialog') : $('#dns-name')).focus();
  }
  async function saveDNSRecord(event) {
    event.preventDefault(); if (!state.user || !cf.zone || cf.recordSaving) return;
    const form = event.currentTarget; const zone = cf.zone; const session = state.session; const record = cf.editorRecord;
    if (!record && cf.records.length >= cf.recordLimit) { showError('#dns-editor-error', `此域名已达到 ${cf.recordLimit} 条记录上限，请先删除不需要的记录。`); return; }
    const type = $('#dns-type').value; const ttl = $('#dns-ttl-mode').value === 'auto' ? 1 : Number($('#dns-ttl').value);
    if (!editableDNSTypes.has(type)) return;
    if (ttl !== 1 && (!Number.isInteger(ttl) || ttl < 60 || ttl > 86400)) { showError('#dns-editor-error', 'TTL 请选择自动，或填写 60–86400 秒。'); return; }
    const body = {type, name: relativeDNSName($('#dns-name').value, zone.name), content: type === 'TXT' ? $('#dns-txt-content').value : $('#dns-content').value.trim(), ttl, proxied: ['A', 'AAAA', 'CNAME'].includes(type) && $('#dns-proxied').checked, comment: $('#dns-comment').value.trim() || null};
    if (type === 'MX') body.priority = Number($('#dns-priority').value);
    cf.recordSaving = true; setBusy(form, true, '正在同步到 Cloudflare…'); showError('#dns-editor-error', '');
    try {
      await api(record ? `${cfRecordsPath(zone.id)}/${encodeURIComponent(record.id)}` : cfRecordsPath(zone.id), {method: record ? 'PUT' : 'POST', body});
      if (session !== state.session) return;
      cf.recordSaving = false; closeDNSEditor(); toast(record ? 'DNS 记录已更新' : 'DNS 记录已添加');
      if (cf.zone?.id === zone.id) await loadCFRecords(zone);
    } catch (error) { if (session === state.session) showError('#dns-editor-error', error.message); }
    finally { if (session === state.session) { cf.recordSaving = false; setBusy(form, false); } }
  }
  async function deleteDNSRecord(record, button) {
    if (!state.user || !cf.zone || !editableDNSTypes.has(record.type)) return;
    const zone = cf.zone; const session = state.session;
    if (!window.confirm(`确认从 Cloudflare 删除这条 DNS 记录？\n\n域名：${zone.name}\n类型：${record.type}\n名称：${record.name}\n内容：${record.content}\n\n删除后该解析将失效。`)) return;
    button.disabled = true; button.textContent = '删除中…'; showError('#cf-records-error', '');
    try {
      await api(`${cfRecordsPath(zone.id)}/${encodeURIComponent(record.id)}`, {method: 'DELETE'});
      if (session !== state.session) return;
      toast('DNS 记录已删除'); if (cf.zone?.id === zone.id) await loadCFRecords(zone);
    } catch (error) { if (session === state.session) { showError('#cf-records-error', error.message); button.disabled = false; button.textContent = '删除'; } }
  }

  function bindEvents() {
    document.addEventListener('click', event => {
      const navigate = event.target.closest('[data-view]'); if (navigate) { changeView(navigate.dataset.view); return; }
      const newTask = event.target.closest('[data-new-kind]'); if (newTask) { $(`input[name="kind"][value="${newTask.dataset.newKind}"]`).checked = true; updateTaskForm(); changeView('create'); return; }
      const toggle = event.target.closest('[data-password-target]'); if (toggle) { const input = document.getElementById(toggle.dataset.passwordTarget); const show = input.type === 'password'; input.type = show ? 'text' : 'password'; toggle.textContent = show ? '隐藏' : '显示'; toggle.setAttribute('aria-label', show ? '隐藏密码' : '显示密码'); }
    });
    $$('.brand').forEach(brand => brand.addEventListener('click', event => { if (state.user) { event.preventDefault(); changeView('overview'); } }));
    $('#menu-button').addEventListener('click', () => { const open = $('#sidebar').classList.toggle('open'); $('#sidebar-backdrop').hidden = !open; $('#menu-button').setAttribute('aria-expanded', String(open)); });
    $('#sidebar-backdrop').addEventListener('click', closeMenu);
    document.addEventListener('keydown', event => { if (event.key === 'Escape') { closeMenu(); closeDNSEditor(); closeDomainAccess(); } });
    $('#login-form').addEventListener('submit', async event => {
      event.preventDefault(); const form = event.currentTarget; setBusy(form, true, '正在登录…'); showError('#login-error', '');
      try { if (!state.csrf) await api('/api/me'); const data = await api('/api/login', {method: 'POST', body: {username: $('#login-username').value.trim(), password: $('#login-password').value}}); if (!data.user) throw new Error('服务未返回登录信息，请重试。'); showApp(data.user); }
      catch (error) { showError('#login-error', error.message); } finally { setBusy(form, false); }
    });
    $('#logout-button').addEventListener('click', async event => {
      const button = event.currentTarget; button.disabled = true;
      try { await api('/api/logout', {method: 'POST'}); endSession(); showError('#login-error', ''); }
      catch (error) { toast(error.message); } finally { button.disabled = false; }
    });
    $('#task-form').addEventListener('input', updateTaskForm); $('#task-form').addEventListener('change', updateTaskForm); $('#task-form').addEventListener('submit', submitTask);
    $('#database-file').addEventListener('change', showFile);
    const zone = $('#upload-zone');
    ['dragenter', 'dragover'].forEach(type => zone.addEventListener(type, event => { event.preventDefault(); zone.classList.add('dragover'); }));
    ['dragleave', 'drop'].forEach(type => zone.addEventListener(type, event => { event.preventDefault(); zone.classList.remove('dragover'); }));
    zone.addEventListener('drop', event => { if (event.dataTransfer.files.length) { const transfer = new DataTransfer(); transfer.items.add(event.dataTransfer.files[0]); $('#database-file').files = transfer.files; showFile(); } });
    $$('.filter-tab').forEach(button => button.addEventListener('click', () => { state.filter = button.dataset.filter; $$('.filter-tab').forEach(item => item.classList.toggle('active', item === button)); renderTasks(); }));
    $('#history-refresh').addEventListener('click', () => loadTasks(true));
    $('#refresh-button').addEventListener('click', () => { loadTasks(true); if (state.view === 'detail') pollTask(); });
    $('#execution-refresh').addEventListener('click', () => { loadTasks(true); if (state.view === 'detail') pollTask(); });
    $('#back-to-history').addEventListener('click', () => changeView('history'));
    $('#copy-url').addEventListener('click', async () => {
      const url = safePanelURL($('#result-url').getAttribute('href'));
      if (!url) return;
      try { await navigator.clipboard.writeText(url); toast('面板地址已复制'); }
      catch { const selection = window.getSelection(); const range = document.createRange(); range.selectNodeContents($('#result-url')); selection.removeAllRanges(); selection.addRange(range); toast('无法自动复制，已选中地址，请手动复制。'); }
    });
    $('#retry-form').addEventListener('submit', async event => {
      event.preventDefault(); if (!state.taskId) return; const form = event.currentTarget; showError('#retry-error', '');
      if (executionBlocked()) { showError('#retry-error', executionMessage()); applySubmissionState(); return; }
      setBusy(form, true, '正在重新提交…');
      try { const data = await api(`/api/tasks/${encodeURIComponent(state.taskId)}/retry`, {method: 'POST', body: {ssh_password: $('#retry-password').value}}); if (!data.task || data.task.id == null) throw new Error('服务未返回新任务编号，请查看任务历史。'); $('#retry-password').value = ''; await openTask(data.task.id); loadTasks(); toast('已创建重试任务'); }
      catch (error) { showError('#retry-error', error.message); } finally { setBusy(form, false); }
    });
    $('#users-refresh').addEventListener('click', loadUsers);
    $('#cf-refresh').addEventListener('click', loadCloudflare);
    $('#cf-config-form').addEventListener('submit', saveCFConfiguration);
    $('#cf-zone-search').addEventListener('input', renderCFZones);
    $('#cf-records-refresh').addEventListener('click', () => loadCFRecords());
    $('#cf-add-record').addEventListener('click', event => openDNSEditor(null, event.currentTarget));
    $('#dns-type').addEventListener('change', updateDNSEditor);
    $('#dns-name').addEventListener('input', updateDNSNamePreview);
    $('#dns-name').addEventListener('change', () => { $('#dns-name').value = relativeDNSName($('#dns-name').value); updateDNSNamePreview(); });
    $('#dns-ttl-mode').addEventListener('change', updateDNSEditor);
    $('#dns-record-form').addEventListener('submit', saveDNSRecord);
    ['#dns-editor-close', '#dns-editor-cancel', '#dns-readonly-close'].forEach(selector => $(selector).addEventListener('click', () => closeDNSEditor()));
    $('#dns-editor-overlay').addEventListener('click', event => { if (event.target === event.currentTarget) closeDNSEditor(); });
    $('#domain-access-form').addEventListener('submit', saveDomainAccess);
    $('#domain-access-search').addEventListener('input', renderDomainAccess);
    ['#domain-access-close', '#domain-access-cancel'].forEach(selector => $(selector).addEventListener('click', () => closeDomainAccess()));
    $('#domain-access-overlay').addEventListener('click', event => { if (event.target === event.currentTarget) closeDomainAccess(); });
    $('#create-user-form').addEventListener('submit', async event => {
      event.preventDefault(); const form = event.currentTarget; showError('#create-user-error', ''); setBusy(form, true, '正在创建…');
      try { await api('/api/admin/users', {method: 'POST', body: {username: $('#new-username').value.trim(), password: $('#new-password').value}}); form.reset(); await loadUsers(); toast('客户账号已创建'); }
      catch (error) { showError('#create-user-error', error.message); } finally { setBusy(form, false); }
    });
    document.addEventListener('visibilitychange', () => { if (!document.hidden && state.user) { loadTasks(); if (state.view === 'detail' && isActive(state.task)) pollTask(); } });
  }
  async function init() {
    let pageReady = false;
    try {
      bindEvents(); updateTaskForm(); pageReady = true;
      const data = await api('/api/me');
      if (data.user) showApp(data.user);
      else { $('#boot-screen').hidden = true; $('#login-screen').hidden = false; }
    } catch (error) {
      if (!pageReady) {
        console.error('工作台页面初始化失败', error);
        const reload = node('button', 'button primary', '重新加载'); reload.type = 'button';
        reload.addEventListener('click', () => window.location.reload());
        const boot = $('#boot-screen'); boot.setAttribute('role', 'alert');
        boot.replaceChildren(node('p', '', '页面加载失败，请重新加载工作台。'), reload);
        return;
      }
      $('#app-shell').hidden = true; $('#boot-screen').hidden = true; $('#login-screen').hidden = false;
      showError('#login-error', error.message);
    }
  }
  init();
})();
