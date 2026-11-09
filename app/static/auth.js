const $ = (selector) => document.querySelector(selector);
const showMessage = (form, message, isError = false) => {
  const box = form.querySelector('.form-message');
  if (box) { box.textContent = message; box.classList.toggle('error', isError); }
};
async function api(path, options = {}) {
  const response = await fetch(path, { credentials: 'same-origin', ...options, headers: { 'Content-Type': 'application/json', ...(options.headers || {}) } });
  let body = {};
  try { body = await response.json(); } catch {}
  if (!response.ok) throw new Error(body.detail || 'Something went wrong. Please try again.');
  return body;
}
function on(formId, handler) {
  const form = document.getElementById(formId);
  if (!form) return;
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const button = form.querySelector('button[type="submit"]');
    button.disabled = true;
    showMessage(form, 'Please wait…');
    try { await handler(new FormData(form), form); }
    catch (error) { showMessage(form, error.message, true); }
    finally { button.disabled = false; }
  });
}
on('register-form', async (data, form) => {
  const username = String(data.get('username')).trim();
  const email = String(data.get('email')).trim().toLowerCase();
  await api('/auth/register/start', { method: 'POST', body: JSON.stringify({ username, email }) });
  sessionStorage.setItem('registerUsername', username);
  sessionStorage.setItem('registerEmail', email);
  location.href = '/static/verify-register.html';
});
const registerEmailLabel = document.getElementById('register-email-label');
if (registerEmailLabel) registerEmailLabel.textContent = sessionStorage.getItem('registerEmail') || 'your email';
on('register-verify-form', async (data, form) => {
  const email = sessionStorage.getItem('registerEmail');
  if (!email) throw new Error('Start account creation again to continue.');
  const result = await api('/auth/register/verify', { method: 'POST', body: JSON.stringify({ email, otp: String(data.get('otp')).trim() }) });
  sessionStorage.setItem('registerVerification', result.verification_token);
  location.href = '/static/create-password.html';
});
on('password-form', async (data, form) => {
  const password = String(data.get('password'));
  if (password !== String(data.get('confirm_password'))) throw new Error('The passwords do not match.');
  const verification_token = sessionStorage.getItem('registerVerification');
  const username = sessionStorage.getItem('registerUsername');
  const email = sessionStorage.getItem('registerEmail');
  if (!verification_token || !username || !email) throw new Error('Verify your email before creating a password.');
  await api('/auth/register/complete', { method: 'POST', body: JSON.stringify({ username, email, verification_token, password }) });
  sessionStorage.removeItem('registerVerification');
  sessionStorage.removeItem('registerUsername');
  sessionStorage.removeItem('registerEmail');
  location.href = '/static/login.html?created=1';
});
on('login-form', async (data, form) => {
  const result = await api('/auth/login/password', { method: 'POST', body: JSON.stringify({ username_or_email: String(data.get('username_or_email')).trim(), password: String(data.get('password')) }) });
  sessionStorage.setItem('loginChallenge', result.challenge_id);
  location.href = '/static/verify-login.html';
});
on('login-verify-form', async (data, form) => {
  const challenge_id = sessionStorage.getItem('loginChallenge');
  if (!challenge_id) throw new Error('Start sign-in again to request a new code.');
  const result = await api('/auth/login/verify-otp', { method: 'POST', body: JSON.stringify({ challenge_id, otp: String(data.get('otp')).trim() }) });
  sessionStorage.removeItem('loginChallenge');
  sessionStorage.setItem('csrfToken', result.csrf_token);
  location.href = '/static/dashboard.html';
});
const usernameNode = document.getElementById('dashboard-username');
if (usernameNode) {
  api('/auth/me').then((user) => {
    usernameNode.textContent = user.username;
    document.getElementById('account-username').textContent = user.username;
    document.getElementById('account-email').textContent = user.email;
  }).catch(() => { location.href = '/static/login.html'; });
}
const logoutButton = document.getElementById('logout-button');
if (logoutButton) logoutButton.addEventListener('click', async () => {
  logoutButton.disabled = true;
  try {
    const csrf = sessionStorage.getItem('csrfToken') || (await api('/auth/csrf')).csrf_token;
    await api('/auth/logout', { method: 'POST', headers: { 'X-CSRF-Token': csrf } });
    sessionStorage.removeItem('csrfToken');
    location.href = '/static/login.html';
  } catch (error) {
    const message = document.getElementById('dashboard-message');
    message.textContent = error.message;
    message.classList.add('error');
    logoutButton.disabled = false;
  }
});
