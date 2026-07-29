'use strict';

let state = { users: [], readOnly: false };

const $ = (id) => document.getElementById(id);

function banner(kind, text) {
  const b = $('banner');
  b.className = kind;
  b.textContent = text;
  b.style.display = text ? 'block' : 'none';
}

async function api(path, body) {
  const opts = {
    method: body === undefined ? 'GET' : 'POST',
    headers: { 'X-Userdb-Admin': '1' },
    credentials: 'same-origin',
  };
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  let data = {};
  try { data = await res.json(); } catch (_) { /* non-JSON error page */ }
  if (!res.ok) {
    const err = new Error(data.error || `HTTP ${res.status}`);
    err.code = data.code;
    throw err;
  }
  return data;
}

// Rejection sampling so there's no modulo bias. 57-char alphabet with no
// look-alikes (no l, I, O, 0, 1) => ~5.83 bits/char, 24 chars => ~140 bits.
function generatePassword(len = 24) {
  const alphabet = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const limit = 256 - (256 % alphabet.length);
  const buf = new Uint8Array(64);
  let out = '';
  while (out.length < len) {
    crypto.getRandomValues(buf);
    for (const b of buf) {
      if (b < limit && out.length < len) out += alphabet[b % alphabet.length];
    }
  }
  return out;
}

function fmtDate(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  return isNaN(d) ? '' : d.toISOString().slice(0, 10);
}

function render() {
  const tbody = $('rows');
  tbody.replaceChildren();

  for (const u of state.users) {
    const tr = document.createElement('tr');

    const tdName = document.createElement('td');
    const code = document.createElement('code');
    code.textContent = u.username;    // textContent, never innerHTML
    tdName.appendChild(code);

    const tdAdded = document.createElement('td');
    tdAdded.className = 'sub';
    tdAdded.style.margin = '0';
    tdAdded.textContent = fmtDate(u.createdAt);

    const tdActions = document.createElement('td');
    tdActions.className = 'row';

    const reset = document.createElement('button');
    reset.type = 'button';
    reset.textContent = 'reset password';
    reset.disabled = state.readOnly;
    reset.addEventListener('click', () => resetUser(u.username));

    const del = document.createElement('button');
    del.type = 'button';
    del.className = 'danger';
    del.textContent = 'delete';
    del.disabled = state.readOnly || state.users.length <= 1;
    if (state.users.length <= 1) del.title = 'cannot delete the last user';
    del.addEventListener('click', () => deleteUser(u.username));

    tdActions.append(reset, del);
    tr.append(tdName, tdAdded, tdActions);
    tbody.appendChild(tr);
  }
}

function apply(data, message) {
  if (data.users) state.users = data.users;
  render();
  banner('ok', message);
}

async function refresh() {
  try {
    const data = await api('/api/users');
    state = { users: data.users || [], readOnly: data.readOnly };
    render();
    if (data.readOnly) banner('warn', 'READ_ONLY is set — all changes are disabled.');
    else if (state.users.length === 0) banner('warn', 'No users yet — the gateway is rejecting every request. Add one below.');
  } catch (e) {
    banner('err', 'could not load users: ' + e.message);
  }
}

async function addUser() {
  const username = $('newUser').value.trim();
  const password = $('newPass').value;
  if (!username || !password) { banner('err', 'username and password are required'); return; }
  $('add').disabled = true;
  try {
    const data = await api('/api/users/add', { username, password });
    apply(data, `added ${username}. Copy the password now: ${password}`);
    $('newUser').value = '';
  } catch (e) { banner('err', e.message); } finally { $('add').disabled = false; }
}

async function resetUser(username) {
  const password = prompt(`New password for ${username}\n(leave as-is to accept the generated one)`, generatePassword());
  if (password === null) return;
  try {
    const data = await api('/api/users/reset', { username, password });
    apply(data, `reset ${username}. Copy the password now: ${password}`);
  } catch (e) { banner('err', e.message); }
}

async function deleteUser(username) {
  const typed = prompt(`Type "${username}" to confirm deletion. This locks them out of the gateway.`);
  if (typed !== username) { banner('warn', 'delete cancelled'); return; }
  try {
    const data = await api('/api/users/delete', { username });
    apply(data, `deleted ${username}.`);
  } catch (e) { banner('err', e.message); }
}

$('gen').addEventListener('click', () => { $('newPass').value = generatePassword(); });
$('add').addEventListener('click', addUser);
$('refresh').addEventListener('click', refresh);

refresh();
