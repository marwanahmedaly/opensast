'use strict';
const $ = id => document.getElementById(id);
const PAGE_SIZE = 25;
let projects = [], spaces = [], active = null, selectedJob = null, result = null;
let editing = null, refreshing = false, submitting = false, reviewSaving = false;
let jobList = [], historyLimit = 10, jobSignature = '', selection = 0;
let routeJob = null;
const summaries = new Map();
const CWE = {22:'Path traversal',78:'Command injection',79:'Cross-site scripting',89:'SQL injection'};
function element(tag, text, className) { const node = document.createElement(tag); if (text != null) node.textContent = text; if (className) node.className = className; return node; }
function message(text = '', tone = 'error') { $('message').textContent = text; $('message').dataset.tone = tone; }
async function perform(action) { try { message(); await action(); } catch (error) { message(error.message || 'Something went wrong. Refresh and try again.'); } }
function button(text, action, disabled = false) {
  const node = element('button', text); node.type = 'button'; node.disabled = disabled;
  node.onclick = () => perform(async () => { node.disabled = true; node.setAttribute('aria-busy','true'); try { await action(); } finally { if (node.isConnected) { node.disabled = disabled; node.removeAttribute('aria-busy'); } } });
  return node;
}
function link(text, href, className = '') { const node = element('a',text,className); node.href = href; return node; }
async function api(path, method = 'GET', body) {
  let response;
  try { response = await fetch('/api' + path, {method, credentials:'same-origin', headers:{'Content-Type':'application/json','X-OpenSAST-CSRF':'1'}, body:body === undefined ? undefined : JSON.stringify(body), signal:AbortSignal.timeout(45000)}); }
  catch (_) { throw new Error('Cannot reach OpenSAST. Check your connection, then use Refresh. Your scan may still be running.'); }
  let value; try { value = await response.json(); } catch (_) { throw new Error('The server returned an unexpected response. Refresh and try again.'); }
  if (!response.ok) { if (response.status === 401) signedOut(); const error = new Error(typeof value.detail === 'string' ? value.detail : 'The request was rejected. Check your access and try again.'); error.status = response.status; throw error; }
  return value;
}
function signedOut() {
  $('session-loading').hidden = true;
  selection++; active = null; projects = []; spaces = []; result = null; selectedJob = null; routeJob = null; jobList = []; summaries.clear();
  $('findings').replaceChildren(); $('jobs').replaceChildren(); $('finding-detail').replaceChildren(); $('secret-value').value = '';
  for (const id of ['secret','editor']) if ($(id).open) $(id).close();
  $('login-panel').hidden = false; $('application').hidden = true; $('breadcrumbs').hidden = true; $('logout').hidden = true; $('password').hidden = true; $('identity').textContent = '';
  document.title = 'OpenSAST · Security workspace';
}
function route() { const match = location.pathname.match(/^\/scans\/([a-f0-9]{32})(?:\/findings\/([^/]+))?\/?$/); return match ? {jid:match[1], fid:match[2] ? decodeURIComponent(match[2]) : null} : null; }
function date(timestamp) { return timestamp ? new Date(timestamp * 1000).toLocaleString() : '—'; }
function duration(seconds) { if (!Number.isFinite(seconds)) return '—'; if (seconds > 0 && seconds < 1) return '<1s'; const s = Math.max(0,Math.floor(seconds)); return s < 60 ? s + 's' : s < 3600 ? Math.floor(s/60) + 'm ' + s%60 + 's' : Math.floor(s/3600) + 'h ' + Math.floor(s%3600/60) + 'm'; }
function liveTime(start) { const node = element('span',duration(Date.now()/1000 - start)); node.dataset.elapsedStart = start; return node; }
function projectUrl(pid) { return '/#project=' + encodeURIComponent(pid); }
function scanUrl(jid, query = '') { return '/scans/' + encodeURIComponent(jid) + query; }
function findingUrl(jid, fid, query = location.search) { return scanUrl(jid) + '/findings/' + encodeURIComponent(fid) + query; }
function badge(text, kind) { return element('span',text,'decision-badge ' + kind); }
function decision(finding) { return finding.verdict === 'VULNERABLE' ? 'flagged' : finding.verdict === 'NOT_VULNERABLE' ? 'not_flagged' : 'needs_review'; }
function decisionLabel(finding) { return {flagged:'Flagged by AI',not_flagged:'Dismissed by AI',needs_review:'Needs review'}[decision(finding)]; }
function counts(findings) { const values = {flagged:0,not_flagged:0,needs_review:0}; for (const finding of findings) values[decision(finding)]++; return values; }
function metric(label,value,caption) { const node = element('div',null,'metric'); node.append(element('strong',String(value)),element('span',label)); if (caption) node.append(element('small',caption)); return node; }
function crumbs(items) {
  $('breadcrumbs').replaceChildren(); $('breadcrumbs').hidden = false;
  items.forEach((item,index) => { if (index) { const sep = element('span','/','crumb-separator'); sep.setAttribute('aria-hidden','true'); $('breadcrumbs').append(sep); } const node = item.href ? link(item.text,item.href) : element('span',item.text); if (!item.href) node.setAttribute('aria-current','page'); $('breadcrumbs').append(node); });
}
function baseCrumbs() { return [{text:'Projects',href:'/'},{text:active.name,href:projectUrl(active.id)}]; }
function form(title, fields, save) {
  $('editor-title').textContent = title; $('editor-fields').replaceChildren();
  for (const field of fields) {
    const label = element('label',field.label); let input;
    if (field.options) { input = element('select'); for (const option of field.options) { const node = element('option',option.label ?? option); node.value = option.value ?? option; input.append(node); } }
    else { input = element('input'); input.type = field.type || 'text'; }
    input.name = field.name; input.required = field.required ?? true; if (field.value != null) input.value = field.value;
    label.append(input); $('editor-fields').append(label);
  }
  editing = save; $('editor').showModal();
}
$('editor-cancel').onclick = () => $('editor').close();
$('editor-form').onsubmit = event => {
  event.preventDefault(); const values = Object.fromEntries(new FormData(event.target)); const submit = event.submitter;
  perform(async () => { if (submit) submit.disabled = true; try { await editing(values); $('editor').close(); } finally { if (submit) submit.disabled = false; } });
};
$('secret-close').onclick = () => { $('secret-value').value = ''; $('secret').close(); };
$('login-form').onsubmit = event => {
  event.preventDefault(); const values = Object.fromEntries(new FormData(event.target)); const submit = event.submitter;
  perform(async () => { submit.disabled = true; submit.textContent = 'Signing in…'; try { await api('/login','POST',values); event.target.reset(); await load(); } finally { submit.disabled = false; submit.textContent = 'Sign in ↗'; } });
};
$('password').onclick = () => form('Change password',[{name:'old_password',label:'Current password',type:'password'},{name:'new_password',label:'New password (at least 12 characters)',type:'password'}],async values => { await api('/password','POST',values); signedOut(); message('Password changed. Sign in again.','success'); });
$('logout').onclick = () => perform(async () => { await api('/logout','POST'); signedOut(); });
async function load() {
  const user = await api('/me'); [spaces,projects] = await Promise.all([api('/workspaces'),api('/projects')]);
  $('session-loading').hidden = true;
  $('identity').textContent = user.username; $('login-panel').hidden = true; $('application').hidden = false; $('logout').hidden = false; $('password').hidden = false;
  const previous = $('workspace').value; $('workspace').replaceChildren();
  for (const space of spaces) { const option = element('option',space.name + ' · ' + space.role); option.value = space.id; $('workspace').append(option); }
  if (spaces.some(space => space.id === previous)) $('workspace').value = previous;
  else if (projects.length) $('workspace').value = projects[0].workspace_id;
  if (route()) { await loadResultPage(); return; }
  const requested = new URLSearchParams(location.hash.slice(1)).get('project');
  const chosen = projects.find(project => project.id === requested);
  if (chosen) { $('workspace').value = chosen.workspace_id; await select(chosen.id,false); }
  else if (!requested && projects.length === 1) { $('workspace').value = projects[0].workspace_id; await select(projects[0].id,false); }
  else { clearProject(); renderProjects(); if (requested) message('This project is not accessible. Choose an available project or ask a workspace administrator.'); }
}
function clearProject() {
  selection++; active = null; result = null; selectedJob = null; jobList = []; jobSignature = '';
  $('project-panel').hidden = true; $('results').hidden = true; $('finding-page').hidden = true; $('empty').hidden = false; $('management').hidden = true;
  const available = projects.filter(project => project.workspace_id === $('workspace').value);
  $('empty-title').textContent = available.length ? 'Select a project' : 'No projects in this workspace';
  $('empty-copy').textContent = available.length ? 'Choose a project on the left to see its scans and findings.' : workspace()?.role === 'admin' ? 'Add a project, then connect its local checkout with opensast init.' : 'Ask a workspace administrator to register a project or add you to another workspace.';
  $('empty-add').hidden = !!available.length || workspace()?.role !== 'admin';
  crumbs([{text:'Projects'}]);
}
function workspace() { return spaces.find(space => space.id === $('workspace').value); }
function renderProjects() {
  $('projects').replaceChildren(); const admin = workspace()?.role === 'admin'; $('new-project').disabled = !admin; $('audit').disabled = !admin;
  const available = projects.filter(project => project.workspace_id === $('workspace').value);
  for (const project of available) { const node = button(project.name,() => select(project.id)); node.className = 'project-button' + (active?.id === project.id ? ' selected' : ''); if (active?.id === project.id) node.setAttribute('aria-current','page'); $('projects').append(node); }
  if (!available.length) $('projects').append(element('p','No projects yet.','hint sidebar-empty'));
}
$('workspace').onchange = () => { history.replaceState(null,'','/'); clearProject(); renderProjects(); };
async function select(pid, push = true) {
  const epoch = ++selection;
  if (route()) { location.href = projectUrl(pid); return; }
  active = projects.find(project => project.id === pid); if (!active) return;
  if (push) history.pushState(null,'',projectUrl(pid)); else history.replaceState(null,'',projectUrl(pid));
  $('workspace').value = active.workspace_id; result = null; selectedJob = null; jobSignature = ''; historyLimit = 10;
  $('management').hidden = true; $('project-panel').hidden = false; $('results').hidden = true; $('finding-page').hidden = true; $('empty').hidden = true;
  $('project-name').textContent = active.name; document.title = active.name + ' · OpenSAST';
  $('worker-token').disabled = active.role !== 'admin';
  $('project-summary').replaceChildren(element('p','Loading latest scan…','hint'));
  $('jobs').replaceChildren(element('p','Loading scan history…','hint'));
  jobList = []; $('scan').disabled = true; $('full-scan').disabled = true;
  crumbs([{text:'Projects',href:'/'},{text:active.name}]); renderProjects(); workerStatus(); await jobs(epoch);
}
function workerOnline() { return active?.worker_seen && Date.now()/1000 - active.worker_seen < 30; }
function workerStatus() {
  if (!active) return;
  const online = workerOnline(); $('worker-state').textContent = online ? 'Worker connected · last seen ' + date(active.worker_seen) : 'Worker offline · queued scans will wait';
  $('worker-state').dataset.online = online ? 'true' : 'false'; $('worker-help').hidden = !!online;
}
function scanButtons() {
  const busy = submitting || jobList.some(job => ['queued','running'].includes(job.status));
  $('scan').disabled = busy || active?.role === 'viewer'; $('full-scan').disabled = busy || active?.role === 'viewer';
  $('scan').textContent = submitting ? 'Queueing…' : busy ? 'Scan in progress' : 'Scan changes';
  $('scan').setAttribute('aria-busy',String(submitting));
}
async function queueScan(full) {
  if (!active || submitting || jobList.some(job => ['queued','running'].includes(job.status))) return;
  const pid = active.id; submitting = true; scanButtons();
  try { await api('/projects/' + pid + '/jobs','POST',{full}); if (active?.id !== pid) return; message(workerOnline() ? 'Scan queued. Progress will update automatically below.' : 'Scan queued. Start opensast worker from the registered project directory to begin.','success'); await jobs(); }
  finally { submitting = false; scanButtons(); }
}
async function jobs(epoch = selection) {
  if (!active) return; const pid = active.id; const list = await api('/projects/' + pid + '/jobs'); if (active?.id !== pid || epoch !== selection) return;
  jobList = list; scanButtons();
  const signature = JSON.stringify(list.map(job => [job.id,job.status,job.started,job.finished,job.error,job.cancel,job.progress]));
  if (signature !== jobSignature) { jobSignature = signature; renderHistory(); }
  renderProgress();
  const completed = list.find(job => job.status === 'completed');
  let latest = null;
  if (completed) { if (!summaries.has(completed.id)) { const data = await api('/jobs/' + completed.id + '/results'); summaries.set(completed.id,{counts:counts(data.findings),total:data.findings.length}); } latest = summaries.get(completed.id); }
  if (active?.id !== pid || epoch !== selection) return;
  renderProjectSummary(list[0],completed,latest);
}
function renderProjectSummary(latest,completed,report) {
  const metrics = element('div',null,'metrics project-metrics');
  metrics.append(metric('Latest scan',latest ? latest.status[0].toUpperCase() + latest.status.slice(1) : 'Not scanned',latest ? date(latest.created) : 'Start the first full scan'));
  metrics.append(metric('Last completed',completed ? date(completed.finished) : '—',completed ? (completed.full ? 'Full scan' : 'Incremental scan') : 'No completed scans yet'));
  metrics.append(metric('Flagged by AI',report ? report.counts.flagged : '—','In the latest completed scan'));
  metrics.append(metric('Needs review',report ? report.counts.needs_review : '—','Missing evidence or verification errors'));
  $('project-summary').replaceChildren(metrics);
  if (completed) $('project-summary').append(link('View latest results →',scanUrl(completed.id),'latest-result-link'));
}
function jobDuration(job) { return job.finished && job.started ? element('span',duration(job.finished - job.started)) : job.status === 'running' && job.started ? liveTime(job.started) : element('span','—'); }
function renderHistory() {
  $('jobs').replaceChildren();
  if (!jobList.length) { const box = element('div',null,'inline-empty'); box.append(element('h3','No scans yet'),element('p',active.role === 'viewer' ? 'A workspace member or administrator can start a scan.' : 'Use Scan changes to start. The first scan analyzes the full repository.')); $('jobs').append(box); return; }
  const wrap = element('div',null,'data-table-wrap'); const table = element('table',null,'data-table history-table'); const head = element('thead'); const row = element('tr');
  for (const label of ['Scan','Status','Duration','Reviewed candidates','Actions']) { const cell = element('th',label); cell.scope = 'col'; row.append(cell); } head.append(row); table.append(head);
  const body = element('tbody');
  for (const job of jobList.slice(0,historyLimit)) {
    const tr = element('tr'); const scan = element('td'); scan.append(element('strong',date(job.created)),element('small',job.full ? 'Full scan' : 'Incremental scan'));
    const details = element('details',null,'scan-id'); details.append(element('summary','Scan details'),element('code',job.id)); if (job.error) details.append(element('p',job.error)); scan.append(details);
    const status = element('td'); status.append(badge(job.cancel && job.status === 'running' ? 'Cancelling' : job.status,job.status));
    const elapsed = element('td'); elapsed.append(jobDuration(job));
    const review = element('td'); const progress = job.progress || {}; review.textContent = progress.total != null && (job.status === 'completed' || progress.total > 0) ? (progress.completed ?? 0) + ' / ' + progress.total : '—';
    const actions = element('td'); const buttons = element('div',null,'actions');
    if (job.status === 'completed') buttons.append(link('View results',scanUrl(job.id),'view-results-link'));
    if (['queued','running'].includes(job.status)) buttons.append(button(job.cancel ? 'Cancelling…' : 'Cancel',async () => { await api('/jobs/' + job.id + '/cancel','POST'); await jobs(); },active.role === 'viewer' || !!job.cancel));
    if (job.status === 'failed') buttons.append(button('Retry scan',() => queueScan(job.full),active.role === 'viewer' || jobList.some(item => ['queued','running'].includes(item.status))));
    actions.append(buttons); tr.append(scan,status,elapsed,review,actions); ['Scan','Status','Duration','Reviewed candidates','Actions'].forEach((label,index) => tr.children[index].dataset.label = label); body.append(tr);
  }
  table.append(body); wrap.append(table); $('jobs').append(wrap);
  if (jobList.length > historyLimit) $('jobs').append(button('Show more scans (' + (jobList.length-historyLimit) + ')',() => { historyLimit += 10; renderHistory(); }));
}
function renderProgress() {
  const current = jobList.find(job => ['queued','running'].includes(job.status)); const box = $('scan-progress');
  box.hidden = !current;
  const notice = $('scan-notice'); notice.replaceChildren(); notice.hidden = true;
  const failed = jobList[0]?.status === 'failed' ? jobList[0] : null;
  if (!current && failed) {
    notice.hidden = false; notice.className = 'notice error';
    notice.append(element('strong','The latest scan failed'),element('p',failed.error || 'The scan did not complete.'),element('p','Check worker and inference availability, then retry. The previous completed report is still available below.'));
    if (active.role !== 'viewer') notice.append(button('Retry scan',() => queueScan(failed.full)));
  }
  if (!current) return;
  const progress = current.progress || {}; const stage = current.status === 'queued' ? 0 : progress.stage === 'verification' ? 2 : progress.stage === 'complete' ? 3 : 1;
  box.replaceChildren(); const top = element('div',null,'section-heading');
  top.append(element('h2',current.status === 'queued' ? 'Scan queued' : current.cancel ? 'Cancelling scan…' : 'Scan in progress'));
  const time = element('span',null,'hint'); time.append(document.createTextNode(current.started ? 'Elapsed ' : 'Waiting '),liveTime(current.started || current.created)); top.append(time); box.append(top);
  const steps = element('ol',null,'scan-steps'); ['Queued','Code analysis','AI review','Completed'].forEach((name,index) => { const step = element('li',name,index < stage ? 'done' : index === stage ? 'current' : ''); if (index === stage) step.setAttribute('aria-current','step'); steps.append(step); }); box.append(steps);
  const status = element('p',null,'progress-copy'); status.setAttribute('role','status');
  if (current.status === 'queued') status.textContent = workerOnline() ? 'Waiting for the connected worker to pick up this scan.' : 'Waiting for a worker. Run opensast worker from the registered project directory.';
  else if (stage === 2) status.textContent = (progress.completed ?? 0) + ' of ' + (progress.total ?? 0) + ' candidates reviewed · ' + (progress.verified ?? 0) + ' sent to AI · ' + (progress.reused ?? 0) + ' reused decisions.';
  else if (stage === 3) status.textContent = 'Saving the scan report. Results will be available shortly.';
  else status.textContent = 'Analyzing repository-wide flows and gathering code evidence. Candidate counts appear when AI review begins.';
  box.append(status);
  if (stage === 2 && progress.total > 0) { const meter = element('progress'); meter.max = progress.total; meter.value = progress.completed ?? 0; meter.setAttribute('aria-label','Candidate review progress'); box.append(meter); }
}
function queryFilters() {
  const params = new URLSearchParams(location.search);
  const rawPage = Number(params.get('page'));
  return {verdict:['flagged','not_flagged','needs_review'].includes(params.get('verdict')) ? params.get('verdict') : '',review:['open','confirmed','dismissed'].includes(params.get('review')) ? params.get('review') : '',q:params.get('q') || '',page:Number.isSafeInteger(rawPage) && rawPage > 0 ? rawPage : 1};
}
function filteredFindings() {
  if (!result) return []; const filters = queryFilters(); const q = filters.q.trim().toLowerCase();
  return result.findings.filter(finding => (!filters.verdict || decision(finding) === filters.verdict) && (!filters.review || (finding.triage?.state || 'open') === filters.review) && (!q || [finding.location.file,finding.rule_id,finding.cwe,CWE[finding.cwe],finding.explanation].join(' ').toLowerCase().includes(q))).sort((a,b) => ({flagged:0,needs_review:1,not_flagged:2}[decision(a)] - {flagged:0,needs_review:1,not_flagged:2}[decision(b)]));
}
function updateFilters(reset = true) {
  const params = new URLSearchParams(); if ($('verdict').value) params.set('verdict',$('verdict').value); if ($('review-filter').value) params.set('review',$('review-filter').value); if ($('finding-search').value) params.set('q',$('finding-search').value);
  if (!reset && queryFilters().page > 1) params.set('page',queryFilters().page);
  history.replaceState(null,'',location.pathname + (params.size ? '?' + params : '')); renderFindings();
}
async function loadResultPage() {
  const current = route(); if (!current) return;
  selection++; $('application').classList.add('scan-results-page'); document.querySelector('.toolbar').hidden = true; document.querySelector('.project-sidebar').hidden = true;
  $('project-panel').hidden = true; $('management').hidden = true; $('empty').hidden = true; $('results').hidden = true; $('finding-page').hidden = true;
  crumbs([{text:'Projects',href:'/'},{text:'Scan results'}]);
  routeJob = await api('/jobs/' + current.jid); active = projects.find(project => project.id === routeJob.project_id);
  if (!active) throw new Error('This scan project is not accessible. Return to Projects or ask a workspace administrator.');
  $('workspace').value = active.workspace_id; selectedJob = current.jid;
  if (routeJob.status !== 'completed') {
    $('results').hidden = false; $('result-page-title').textContent = 'Results are not ready'; $('result-project-name').textContent = active.name;
    $('back-to-project').href = projectUrl(active.id); $('summary').replaceChildren(element('p','This scan is ' + routeJob.status + '. Return to scan history to follow its progress.')); $('result-controls').hidden = true; $('export').hidden = true; $('findings').replaceChildren();
    crumbs([...baseCrumbs(),{text:'Scan results'}]); return;
  }
  result = await api('/jobs/' + current.jid + '/results');
  document.title = active.name + ' · ' + (current.fid ? 'Finding review' : 'Scan results') + ' · OpenSAST';
  if (current.fid) { renderFindingPage(current.fid); return; }
  $('results').hidden = false; $('export').hidden = false; $('result-controls').hidden = false;
  $('back-to-project').href = projectUrl(active.id); $('result-project-name').textContent = active.name;
  $('result-page-title').textContent = 'Scan results'; $('result-scan-meta').textContent = (routeJob.full ? 'Full scan' : 'Incremental scan') + ' · Completed ' + date(routeJob.finished);
  $('export').href = '/api/jobs/' + current.jid + '/export'; crumbs([...baseCrumbs(),{text:'Scan results'}]);
  const filters = queryFilters(); $('verdict').value = filters.verdict; $('review-filter').value = filters.review; $('finding-search').value = filters.q;
  renderResultSummary(); renderFindings();
}
function renderResultSummary() {
  const totals = counts(result.findings); const metrics = element('div',null,'metrics outcome-metrics');
  metrics.append(metric('Flagged by AI',totals.flagged,'Potential vulnerabilities to inspect'),metric('Dismissed by AI',totals.not_flagged,'Not a human review decision'),metric('Needs review',totals.needs_review,'Missing evidence or verification errors'),metric('Total candidates',result.findings.length,'All candidates in this scan'));
  $('summary').replaceChildren(metrics,element('p','These are AI decisions, not confirmed ground truth. Human confirmation and dismissal are recorded separately.','hint'));
  if (!result.summary.verifier_configured) $('summary').append(element('p','AI verification was not configured. These are unverified suspects. Configure inference and rescan.','notice warning'));
  else if (totals.needs_review) $('summary').append(element('p','Some candidates could not be resolved. Filter Needs review to inspect the missing evidence or verification error.','notice warning'));
  const details = element('details',null,'scan-technical'); details.append(element('summary','Scan timing, reuse and technical details'));
  const metrics2 = element('div',null,'metrics'); metrics2.append(metric('Duration',duration(result.summary.elapsed_seconds)),metric('Reused decisions',result.summary.reused ?? 0),metric('Sent to AI',result.summary.verified ?? 0),metric('Scan type',routeJob.full ? 'Full' : 'Incremental'));
  details.append(metrics2,element('p',result.summary.scanner_scope),element('p','Scan ID: ' + selectedJob,'hint'),element('pre',JSON.stringify(result.summary,null,2))); $('summary').append(details);
}
function renderFindings() {
  $('findings').replaceChildren(); const findings = filteredFindings(); const filters = queryFilters();
  const pages = Math.max(1,Math.ceil(findings.length/PAGE_SIZE)); const page = Math.min(filters.page,pages); const start = (page-1)*PAGE_SIZE;
  $('finding-count').textContent = findings.length + ' of ' + result.findings.length + ' candidates';
  if (!findings.length) { const box = element('div',null,'inline-empty'); box.append(element('h3',result.findings.length ? 'No matching findings' : 'No candidates were reported'),element('p',result.findings.length ? 'Try another filter or clear your search.' : 'The scanner reported no candidates within its coverage. This is not proof that the repository is vulnerability-free.')); if (result.findings.length) box.append(button('Clear filters',resetFilters)); $('findings').append(box); return; }
  const wrap = element('div',null,'data-table-wrap'); const table = element('table',null,'data-table findings-table'); const head = element('thead'); const row = element('tr');
  for (const label of ['Finding','Location','AI decision','Human review','']) { const cell = element('th',label); cell.scope = 'col'; if (!label) cell.setAttribute('aria-label','Open finding'); row.append(cell); } head.append(row); table.append(head); const body = element('tbody');
  for (const finding of findings.slice(start,start+PAGE_SIZE)) {
    const tr = element('tr'); const title = element('td'); title.append(element('strong',CWE[finding.cwe] || 'Security finding'),element('small','CWE-' + finding.cwe));
    const source = element('td'); source.append(element('code',finding.location.file + ':' + finding.location.line));
    const model = element('td'); model.append(badge(decisionLabel(finding),decision(finding)));
    const human = element('td'); human.append(badge(finding.triage?.state || 'open','review-' + (finding.triage?.state || 'open')));
    const action = element('td'); const params = new URLSearchParams(location.search); if (page > 1) params.set('page',page); const query = params.size ? '?' + params : ''; action.append(link('Review finding →',findingUrl(selectedJob,finding.finding_id,query),'finding-link'));
    tr.append(title,source,model,human,action); ['Finding','Location','AI decision','Human review','Action'].forEach((label,index) => tr.children[index].dataset.label = label); body.append(tr);
  }
  table.append(body); wrap.append(table); $('findings').append(wrap);
  const navigation = element('div',null,'pagination'); const change = next => { const params = new URLSearchParams(location.search); if (next > 1) params.set('page',next); else params.delete('page'); history.replaceState(null,'',location.pathname + (params.size ? '?' + params : '')); renderFindings(); $('findings').scrollIntoView({block:'start'}); };
  navigation.append(element('span','Showing ' + (start+1) + '–' + Math.min(start+PAGE_SIZE,findings.length) + ' of ' + findings.length),button('Previous',() => change(page-1),page === 1),element('span','Page ' + page + ' of ' + pages),button('Next',() => change(page+1),page === pages)); $('findings').append(navigation);
}
function resetFilters() { $('verdict').value = ''; $('review-filter').value = ''; $('finding-search').value = ''; updateFilters(); }
function renderFindingPage(fid) {
  $('finding-page').hidden = false; $('finding-detail').replaceChildren();
  const finding = result.findings.find(item => item.finding_id === fid);
  $('back-to-results').href = scanUrl(selectedJob,location.search);
  if (!finding) { $('finding-title').textContent = 'Finding not found'; $('finding-subtitle').textContent = 'This finding is not part of the selected scan. Return to its result list.'; crumbs([...baseCrumbs(),{text:'Scan results',href:scanUrl(selectedJob,location.search)},{text:'Finding not found'}]); return; }
  $('finding-title').textContent = CWE[finding.cwe] || 'Security finding'; $('finding-subtitle').textContent = 'CWE-' + finding.cwe + ' · ' + finding.location.file + ':' + finding.location.line;
  crumbs([...baseCrumbs(),{text:'Scan results',href:scanUrl(selectedJob,location.search)},{text:'CWE-' + finding.cwe}]);
  const navigation = $('finding-navigation'); navigation.replaceChildren(); const findings = filteredFindings(); const index = findings.findIndex(item => item.finding_id === fid);
  if (index >= 0) {
    const navLink = (text,target) => { const params = new URLSearchParams(location.search); const page = Math.floor(target/PAGE_SIZE)+1; if (page > 1) params.set('page',page); else params.delete('page'); return link(text,findingUrl(selectedJob,findings[target].finding_id,params.size ? '?' + params : ''),'view-results-link'); };
    if (index > 0) navigation.append(navLink('← Previous finding',index-1)); navigation.append(element('span',(index+1) + ' of ' + findings.length + ' matching findings','hint')); if (index+1 < findings.length) navigation.append(navLink('Next finding →',index+1));
  }
  const layout = element('div',null,'finding-review-layout'); const evidence = element('section',null,'evidence-panel'); evidence.append(element('h2','Code evidence'),element('p','Referenced excerpts supplied to the verifier. The reported operation is expanded first; open other excerpts for supporting context.','hint'));
  if (!(finding.evidence || []).length) evidence.append(element('p','No code excerpts are attached. Review the source repository before confirming this finding.','notice warning'));
  const blocks = finding.evidence || [];
  let preferred = blocks.findIndex(block => block.kind === 'sink' && block.file === finding.location.file && block.start_line <= finding.location.line && block.end_line >= finding.location.line);
  if (preferred < 0) preferred = blocks.findIndex(block => block.file === finding.location.file && block.start_line <= finding.location.line && block.end_line >= finding.location.line);
  if (preferred < 0 && blocks.length) preferred = 0;
  blocks.forEach((block,index) => {
    const box = element('details',null,'evidence-block'); box.open = index === preferred;
    const summary = element('summary'); const title = element('span'); title.append(element('strong',String(block.kind || 'Evidence').replaceAll('_',' ')),element('small',block.file + ':' + block.start_line + '–' + block.end_line)); summary.append(title); box.append(summary);
    if (block.truncated) box.append(element('p','This excerpt is truncated' + (block.source_end_line ? '; the original continues through line ' + block.source_end_line : '') + '.','notice warning'));
    const pre = element('pre',null,'numbered-code');
    const lines = String(block.code || '').split('\n');
    if (lines.length > 1 && lines[lines.length-1] === '' && Number(block.start_line)+lines.length-1 > Number(block.end_line)) lines.pop();
    // Context excerpts may already contain "line | code" prefixes. Strip only
    // a complete sequential prefix set; stored evidence remains unchanged.
    const prefixed = lines.some(text => text.trim()) && lines.every((text,offset) => { if (!text.trim()) return true; const match = text.match(/^\s*(\d+) \| ?/); return match && Number(match[1]) === Number(block.start_line)+offset; });
    lines.forEach((original,offset) => { const text = prefixed ? original.replace(/^\s*\d+ \| ?/,'') : original; const line = Number(block.start_line)+offset; const row = element('span',null,'code-line' + (block.file === finding.location.file && line === finding.location.line ? ' reported-line' : '')); const number = element('span',line,'line-number'); number.setAttribute('aria-hidden','true'); row.append(number,element('code',text || ' ')); pre.append(row); }); box.append(pre); evidence.append(box);
  });
  const review = element('section',null,'review-panel'); review.append(element('h2','AI assessment'),badge(decisionLabel(finding),decision(finding)),element('p',finding.explanation || 'No explanation was supplied.','assessment-explanation'));
  const verdict = element('p','Verification verdict: ' + finding.verdict,'hint'); review.append(verdict);
  if ((finding.validation_errors || []).length) review.append(element('h3','Evidence or validation issues'),element('pre',JSON.stringify(finding.validation_errors,null,2)));
  const human = element('section',null,'human-review'); human.append(element('h2','Human review'),element('p','Your decision is stored separately from the AI verdict.','hint'));
  const status = badge(finding.triage?.state || 'open','review-' + (finding.triage?.state || 'open')); status.id = 'human-review-state'; human.append(status);
  const label = element('label','Review note'); const notes = element('textarea'); notes.id = 'review-note'; notes.rows = 5; notes.value = finding.triage?.note || ''; notes.placeholder = 'Record the reasoning and supporting evidence.'; notes.disabled = active.role === 'viewer'; label.append(notes); human.append(label);
  const actions = element('div',null,'actions review-actions');
  const save = async state => {
    if (reviewSaving || active.role === 'viewer') return; reviewSaving = true;
    for (const node of actions.querySelectorAll('button')) node.disabled = true;
    const note = notes.value;
    try {
      await api('/jobs/' + selectedJob + '/findings/' + encodeURIComponent(fid) + '/review','POST',{state,note}); finding.triage = {state,note};
      status.textContent = state; status.className = 'decision-badge review-' + state; feedback.textContent = 'Review saved.';
      for (const node of actions.querySelectorAll('button[data-state]')) node.setAttribute('aria-pressed',String(node.dataset.state === state));
    } catch (error) { feedback.textContent = error.message; message('Review was not saved. Your note is still here. ' + error.message); }
    finally { reviewSaving = false; for (const node of actions.querySelectorAll('button')) node.disabled = active.role === 'viewer'; }
  };
  for (const [text,state] of [['Confirm finding','confirmed'],['Dismiss finding','dismissed'],['Reopen','open']]) { const node = button(text,() => save(state),active.role === 'viewer'); node.dataset.state = state; node.setAttribute('aria-pressed',String((finding.triage?.state || 'open') === state)); actions.append(node); }
  actions.append(button('Save note',() => save(finding.triage?.state || 'open'),active.role === 'viewer')); human.append(actions);
  const feedback = element('p','','review-feedback'); feedback.setAttribute('role','status'); human.append(feedback);
  if (active.role === 'viewer') human.append(element('p','Read-only access. Ask a workspace member or administrator to record a review.','hint'));
  review.append(human); const details = element('details',null,'finding-technical'); details.append(element('summary','Rule and finding identifiers'),element('p','Rule: ' + finding.rule_id),element('code',finding.finding_id)); review.append(details);
  layout.append(review,evidence); $('finding-detail').append(layout);
}
$('verdict').onchange = () => updateFilters(); $('review-filter').onchange = () => updateFilters(); $('finding-search').oninput = () => updateFilters(); $('clear-filters').onclick = resetFilters;
$('scan').onclick = () => perform(() => queueScan(false)); $('full-scan').onclick = () => perform(() => queueScan(true));
$('worker-token').onclick = () => perform(async () => { if (!confirm('Rotate the project worker credential? The current worker will need the new credential.')) return; const value = await api('/projects/' + active.id + '/worker-token','POST'); $('secret-value').value = value.token; $('secret').showModal(); });
$('new-workspace').onclick = () => form('New workspace',[{name:'name',label:'Workspace name'}],async values => { const created = await api('/workspaces','POST',values); await load(); $('workspace').value = created.id; history.replaceState(null,'','/'); clearProject(); renderProjects(); });
function newProject() { form('New project',[{name:'name',label:'Project name'}],async values => { const project = await api('/projects','POST',{...values,workspace_id:$('workspace').value}); projects = await api('/projects'); await select(project.id); message('Project created. In its local checkout, run: opensast init --project ' + project.id,'success'); }); }
$('new-project').onclick = newProject; $('empty-add').onclick = newProject;
$('members').onclick = () => perform(async () => {
  const wid = $('workspace').value; const list = await api('/workspaces/' + wid + '/members'); $('management').replaceChildren(element('h2','Workspace members')); $('management').hidden = false;
  for (const member of list) $('management').append(element('p',member.username + ' · ' + member.role));
  if (workspace().role === 'admin') $('management').append(button('Add or update member',() => form('Workspace membership',[{name:'username',label:'Username'},{name:'role',label:'Role',options:['member','viewer','admin','remove']},{name:'password',label:'Initial password (new accounts only)',type:'password',required:false}],async values => { if (!values.password) delete values.password; if (values.role === 'remove') values.role = null; await api('/workspaces/' + wid + '/members','POST',values); await load(); $('management').hidden = true; })));
});
$('audit').onclick = () => perform(async () => { const list = await api('/workspaces/' + $('workspace').value + '/audit'); $('management').replaceChildren(element('h2','Workspace audit log'),element('pre',JSON.stringify(list,null,2))); $('management').hidden = false; });
$('refresh').onclick = () => perform(load);
window.addEventListener('popstate',() => { if (!route() && !$('application').hidden) perform(load); });
setInterval(async () => {
  if (refreshing || $('application').hidden || !active || route()) return;
  refreshing = true; const pid = active.id;
  try { const updated = await api('/projects'); if (active?.id !== pid) return; projects = updated; const project = projects.find(item => item.id === pid); if (!project) { clearProject(); renderProjects(); return; } active = project; workerStatus(); $('worker-token').disabled = active.role !== 'admin'; await jobs(); }
  catch (error) { message(error.message); } finally { refreshing = false; }
},5000);
setInterval(() => { for (const node of document.querySelectorAll('[data-elapsed-start]')) node.textContent = duration(Date.now()/1000 - Number(node.dataset.elapsedStart)); },1000);
async function openWorkspace() {
  $('session-loading').hidden = false;
  $('login-panel').hidden = true;
  $('application').hidden = true;
  $('session-title').textContent = 'Opening your workspace…';
  $('session-copy').textContent = 'Checking your session.';
  $('session-retry').hidden = true;
  $('session-loading').classList.remove('load-failed');
  try { await load(); }
  catch (error) {
    if (error.status === 401) return; // signedOut shows login only after a confirmed 401.
    $('session-title').textContent = 'Unable to open your workspace';
    $('session-copy').textContent = error.message;
    $('session-retry').hidden = false;
    $('session-loading').classList.add('load-failed');
    $('session-loading').hidden = false;
    $('application').hidden = true;
  }
}
$('session-retry').onclick = () => perform(openWorkspace);
openWorkspace();
