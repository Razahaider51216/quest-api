const views = {
  loading: document.querySelector("#loading-view"),
  setup: document.querySelector("#setup-view"),
  login: document.querySelector("#login-view"),
  dashboard: document.querySelector("#dashboard-view"),
};

let licenses = [];

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
  if (!value) return "ไม่หมดอายุ";
  return new Intl.DateTimeFormat("th-TH", { dateStyle: "medium" }).format(new Date(value));
}

function escapeText(value) {
  const element = document.createElement("span");
  element.textContent = value;
  return element.innerHTML;
}

function renderLicenses() {
  const body = document.querySelector("#license-table-body");
  const empty = document.querySelector("#empty-state");
  body.innerHTML = licenses.map((license) => `
    <tr>
      <td>${escapeText(license.label || "ไม่มีชื่อ")}</td>
      <td><code>AQ-••••-••••-••••-${escapeText(license.keyLast4)}</code></td>
      <td><span class="status ${license.status}">${license.status === "active" ? "ใช้งานได้" : "ระงับ"}</span></td>
      <td>${escapeText(formatDate(license.expiresAt))}</td>
      <td>${license.deviceCount} / ${license.deviceLimit}</td>
      <td><div class="row-actions">
        ${license.deviceCount ? `<button class="button ghost" data-reset="${license.id}">ล้างเครื่อง</button>` : ""}
        <button class="button ${license.status === "active" ? "danger" : "ghost"}" data-toggle="${license.id}" data-status="${license.status}">${license.status === "active" ? "ระงับ" : "เปิดใช้"}</button>
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
  const [{ admin }, result] = await Promise.all([
    api("/api/admin/me"),
    api("/api/admin/licenses"),
  ]);
  document.querySelector("#admin-email").textContent = admin.email;
  licenses = result.licenses;
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
    views.loading.querySelector("p").textContent = `เชื่อมต่อ API ไม่สำเร็จ: ${error.message}`;
  }
}

document.querySelector("#setup-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = Object.fromEntries(new FormData(form));
  setMessage(form, "กำลังสร้างบัญชี…");
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
  setMessage(form, "กำลังเข้าสู่ระบบ…");
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
    expiresInDays: Number(formData.get("expiresInDays")),
    deviceLimit: Number(formData.get("deviceLimit")),
  };
  setMessage(form, "กำลังสร้าง Key…");
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
  event.currentTarget.textContent = "คัดลอกแล้ว";
  setTimeout(() => { event.currentTarget.textContent = "คัดลอก"; }, 1500);
});

document.querySelector("#refresh-button").addEventListener("click", loadDashboard);

document.querySelector("#license-table-body").addEventListener("click", async (event) => {
  const toggleButton = event.target.closest("[data-toggle]");
  const resetButton = event.target.closest("[data-reset]");
  try {
    if (toggleButton) {
      const status = toggleButton.dataset.status === "active" ? "revoked" : "active";
      const result = await api(`/api/admin/licenses/${toggleButton.dataset.toggle}`, {
        method: "PATCH",
        body: JSON.stringify({ status }),
      });
      licenses = licenses.map((item) => item.id === result.license.id ? result.license : item);
      renderLicenses();
    }
    if (resetButton && confirm("ล้างการผูกเครื่องทั้งหมดของ License นี้หรือไม่?")) {
      await api(`/api/admin/licenses/${resetButton.dataset.reset}/devices`, {
        method: "DELETE",
        body: "{}",
      });
      const result = await api("/api/admin/licenses");
      licenses = result.licenses;
      renderLicenses();
    }
  } catch (error) {
    alert(error.message);
  }
});

initialize();
