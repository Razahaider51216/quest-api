const views = {
  loading: document.querySelector("#loading-view"),
  setup: document.querySelector("#setup-view"),
  login: document.querySelector("#login-view"),
  dashboard: document.querySelector("#dashboard-view"),
};

let licenses = [];
let appSettings = {
  versionLabel: "v0.10.0",
  discordContactUrl: "",
};

function showView(name) {
  Object.entries(views).forEach(([key, view]) => view.classList.toggle("hidden", key !== name));
  document.querySelector("#admin-profile").classList.toggle("hidden", name !== "dashboard");
}

function setMessage(form, message, success = false) {
  const element = form.querySelector(".form-message");
  element.textContent = message;
  element.classList.toggle("success", success);
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    credentials: "same-origin",
    ...options,
    headers: options.body ? { "content-type": "application/json", ...options.headers } : options.headers,
  });
  if (response.status === 204) return null;
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error?.message ?? `Request failed (${response.status})`);
  return body;
}

function formatDate(value) {
  if (!value) return "Never expires";
  return new Intl.DateTimeFormat("th-TH", { dateStyle: "medium" }).format(new Date(value));
}

function escapeText(value) {
  const element = document.createElement("span");
  element.textContent = value;
  return element.innerHTML;
}

function visibleKey(license) {
  if (license.licenseKey && license.showKey) return license.licenseKey;
  return license.licenseKey ? `AQ-....-....-....-${license.keyLast4}` : `AQ-....-....-....-${license.keyLast4}`;
}

function renderLicenses() {
  const body = document.querySelector("#license-table-body");
  const empty = document.querySelector("#empty-state");
  body.innerHTML = licenses.map((license) => `
    <tr>
      <td>${escapeText(license.label || "No label")}</td>
      <td><code>${escapeText(visibleKey(license))}</code></td>
      <td><span class="status ${license.role === "developer" ? "developer" : "customer"}">${license.role === "developer" ? "Developer" : "Customer"}</span></td>
      <td><span class="status ${license.status}">${license.status === "active" ? "Active" : "Revoked"}</span></td>
      <td>${escapeText(formatDate(license.expiresAt))}</td>
      <td>${license.deviceCount} / ${license.deviceLimit}</td>
      <td><div class="row-actions">
        ${license.deviceCount ? `<button class="button ghost" data-reset="${license.id}">Reset devices</button>` : ""}
        <button class="button ${license.status === "active" ? "danger" : "ghost"}" data-toggle="${license.id}" data-status="${license.status}">${license.status === "active" ? "Revoke" : "Activate"}</button>
        <button class="button danger" data-delete="${license.id}">Delete</button>
      </div></td>
    </tr>
  `).join("");
  empty.classList.toggle("hidden", licenses.length > 0);
  document.querySelector("#metric-total").textContent = licenses.length;
  document.querySelector("#metric-active").textContent = licenses.filter((item) => item.status === "active").length;
  document.querySelector("#metric-revoked").textContent = licenses.filter((item) => item.status === "revoked").length;
  document.querySelector("#metric-devices").textContent = licenses.reduce((sum, item) => sum + item.deviceCount, 0);
}

async function loadDashboard() {
  const [{ admin }, result, settingsResult] = await Promise.all([
    api("/api/admin/me"),
    api("/api/admin/licenses"),
    api("/api/admin/settings"),
  ]);
  document.querySelector("#admin-email").textContent = admin.email;
  licenses = result.licenses;
  appSettings = settingsResult.app;
  const settingsForm = document.querySelector("#app-settings-form");
  settingsForm.elements.versionLabel.value = appSettings.versionLabel;
  settingsForm.elements.discordContactUrl.value = appSettings.discordContactUrl;
  renderLicenses();
  showView("dashboard");
}

async function initialize() {
  try {
    const { setupRequired } = await api("/api/setup/status");
    if (setupRequired) {
      showView("setup");
      return;
    }
    try {
      await loadDashboard();
    } catch {
      showView("login");
    }
  } catch (error) {
    views.loading.querySelector("p").textContent = `Cannot connect to API: ${error.message}`;
  }
}

document.querySelector("#setup-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = Object.fromEntries(new FormData(form));
  setMessage(form, "Creating admin account...");
  try {
    await api("/api/setup", { method: "POST", body: JSON.stringify(data) });
    form.reset();
    showView("login");
  } catch (error) {
    setMessage(form, error.message);
  }
});

document.querySelector("#login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = Object.fromEntries(new FormData(form));
  setMessage(form, "Signing in...");
  try {
    await api("/api/admin/login", { method: "POST", body: JSON.stringify(data) });
    form.reset();
    await loadDashboard();
  } catch (error) {
    setMessage(form, error.message);
  }
});

document.querySelector("#logout-button").addEventListener("click", async () => {
  await api("/api/admin/logout", { method: "POST", body: "{}" });
  showView("login");
});

const dialog = document.querySelector("#create-dialog");
document.querySelector("#open-create-button").addEventListener("click", () => dialog.showModal());
document.querySelector("#close-create-button").addEventListener("click", () => dialog.close());

document.querySelector("#create-license-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const formData = new FormData(form);
  const data = {
    label: formData.get("label"),
    role: formData.get("role"),
    expiresInDays: Number(formData.get("expiresInDays")),
    deviceLimit: Number(formData.get("deviceLimit")),
  };
  setMessage(form, "Creating key...");
  try {
    const result = await api("/api/admin/licenses", { method: "POST", body: JSON.stringify(data) });
    licenses.unshift(result.license);
    renderLicenses();
    document.querySelector("#new-license-key").textContent = result.licenseKey;
    document.querySelector("#key-reveal").classList.remove("hidden");
    form.reset();
    form.elements.expiresInDays.value = 30;
    form.elements.deviceLimit.value = 1;
    setMessage(form, "");
    dialog.close();
  } catch (error) {
    setMessage(form, error.message);
  }
});

document.querySelector("#copy-key-button").addEventListener("click", async (event) => {
  await navigator.clipboard.writeText(document.querySelector("#new-license-key").textContent);
  event.currentTarget.textContent = "Copied";
  setTimeout(() => { event.currentTarget.textContent = "Copy"; }, 1500);
});

document.querySelector("#refresh-button").addEventListener("click", loadDashboard);

document.querySelector("#app-settings-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = Object.fromEntries(new FormData(form));
  setMessage(form, "Saving settings...");
  try {
    const result = await api("/api/admin/settings", {
      method: "PATCH",
      body: JSON.stringify(data),
    });
    appSettings = result.app;
    form.elements.versionLabel.value = appSettings.versionLabel;
    form.elements.discordContactUrl.value = appSettings.discordContactUrl;
    setMessage(form, "Settings saved.", true);
  } catch (error) {
    setMessage(form, error.message);
  }
});

document.querySelector("#license-table-body").addEventListener("click", async (event) => {
  const toggleButton = event.target.closest("[data-toggle]");
  const resetButton = event.target.closest("[data-reset]");
  const copyButton = event.target.closest("[data-copy-license]");
  const deleteButton = event.target.closest("[data-delete]");
  try {
    if (copyButton) {
      const license = licenses.find((item) => item.id === copyButton.dataset.copyLicense);
      if (license?.licenseKey) {
        await navigator.clipboard.writeText(license.licenseKey);
        copyButton.textContent = "Copied";
        setTimeout(() => { copyButton.textContent = "Copy"; }, 1500);
      }
      return;
    }

    if (toggleButton) {
      const status = toggleButton.dataset.status === "active" ? "revoked" : "active";
      const result = await api(`/api/admin/licenses/${toggleButton.dataset.toggle}`, {
        method: "PATCH",
        body: JSON.stringify({ status }),
      });
      licenses = licenses.map((item) => item.id === result.license.id ? result.license : item);
      renderLicenses();
      return;
    }

    if (resetButton && confirm("Reset all activated devices for this license?")) {
      await api(`/api/admin/licenses/${resetButton.dataset.reset}/devices`, {
        method: "DELETE",
        body: "{}",
      });
      const result = await api("/api/admin/licenses");
      licenses = result.licenses;
      renderLicenses();
      return;
    }

    if (deleteButton && confirm("Delete this license key? This cannot be undone.")) {
      await api(`/api/admin/licenses/${deleteButton.dataset.delete}`, {
        method: "DELETE",
        body: "{}",
      });
      licenses = licenses.filter((item) => item.id !== deleteButton.dataset.delete);
      renderLicenses();
    }
  } catch (error) {
    alert(error.message);
  }
});

initialize();
