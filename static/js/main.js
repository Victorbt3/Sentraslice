// --- Sentraslice Global SPA Controller ---

// Global Application State
const State = {
  user: null,
  slices: [],
  notifications: [],
  currentAssessmentId: null,
  activeView: 'landing',
  activeWorkspaceView: 'overview',
  theme: 'dark'
};

// DOM Elements Loader
document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  checkSession();
  setupNavigation();
  setupAuthHandlers();
  setupSliceHandlers();
  setupSettingsHandlers();
  
  // Start background notifications fetch
  setInterval(fetchNotifications, 10000);
});

// --- Theme Controller ---
function initTheme() {
  const savedTheme = localStorage.getItem('theme') || 'dark';
  setTheme(savedTheme);
  
  const toggles = document.querySelectorAll('.theme-toggle');
  toggles.forEach(t => {
    t.addEventListener('click', () => {
      const newTheme = State.theme === 'dark' ? 'light' : 'dark';
      setTheme(newTheme);
    });
  });
}

function setTheme(theme) {
  State.theme = theme;
  localStorage.setItem('theme', theme);
  
  const body = document.body;
  if (theme === 'light') {
    body.classList.add('light-mode');
  } else {
    body.classList.remove('light-mode');
  }
  
  // Update icons or labels if any
  const icons = document.querySelectorAll('.theme-toggle i');
  icons.forEach(icon => {
    if (theme === 'light') {
      icon.className = 'fas fa-moon';
    } else {
      icon.className = 'fas fa-sun';
    }
  });
}

// --- Session Synchronization ---
async function checkSession() {
  try {
    const res = await fetch('/api/auth/me');
    const data = await res.json();
    
    if (data.authenticated) {
      State.user = data.user;
      updateUserUI();
      // If user is authenticated, skip landing/auth unless URL dictates otherwise
      showView('workspace');
      showWorkspaceView('overview');
    } else {
      showView('landing');
    }
  } catch (err) {
    console.error('Session sync error:', err);
    showView('landing');
  }
}

// --- Navigation Engine (SPA Router) ---
function showView(viewId) {
  State.activeView = viewId;
  
  // Hide all root layouts
  document.querySelectorAll('.root-layout').forEach(el => {
    el.style.display = 'none';
  });
  
  // Show target layout
  if (viewId === 'landing') {
    document.getElementById('landingView').style.display = 'flex';
    // Initialize landing network particles
    if (window.initLandingAnimation) window.initLandingAnimation();
  } else if (viewId === 'auth') {
    document.getElementById('authView').style.display = 'grid';
    if (window.initAuthAnimation) window.initAuthAnimation();
  } else if (viewId === 'workspace') {
    document.getElementById('workspaceView').style.display = 'grid';
  }
}

function showWorkspaceView(subViewId) {
  State.activeWorkspaceView = subViewId;
  
  // Update main content viewport header
  const titleMap = {
    overview: 'Assessment Overview',
    slices: 'Network Slice Management',
    scanner: 'Vulnerability Assessment Engine',
    threats: 'Threat Center & Remediation Guides',
    analytics: 'Security Analytics & Threat Intel',
    reports: 'Compliance Reports Exporter',
    audit: 'Operator Audit Trail Logs',
    settings: 'Platform Security Settings',
    users: 'Admin User Management'
  };
  
  const titleEl = document.getElementById('viewportTitle');
  if (titleEl && titleMap[subViewId]) {
    titleEl.innerText = titleMap[subViewId];
  }
  
  // Toggle active views
  document.querySelectorAll('.app-view-section').forEach(el => {
    el.classList.remove('active-view');
  });
  
  const targetView = document.getElementById(`${subViewId}View`);
  if (targetView) {
    targetView.classList.add('active-view');
  }
  
  // Toggle sidebar items
  document.querySelectorAll('.sidebar-item').forEach(el => {
    el.classList.remove('active-menu');
    if (el.dataset.view === subViewId) {
      el.classList.add('active-menu');
    }
  });
  
  // Run specific view loading scripts
  if (subViewId === 'overview') {
    fetchDashboardData();
  } else if (subViewId === 'slices') {
    fetchSlices();
  } else if (subViewId === 'scanner') {
    initScannerView();
  } else if (subViewId === 'threats') {
    fetchVulnerabilities();
  } else if (subViewId === 'analytics') {
    fetchAnalytics();
  } else if (subViewId === 'reports') {
    fetchReports();
  } else if (subViewId === 'audit') {
    fetchAuditLogs();
  } else if (subViewId === 'settings') {
    fetchSettings();
  } else if (subViewId === 'users') {
    fetchUsers();
  }
}

function setupNavigation() {
  // Landing CTAs
  document.getElementById('landingToAuthBtn').addEventListener('click', () => showView('auth'));
  document.getElementById('landingToDashboardBtn').addEventListener('click', () => {
    if (State.user) {
      showView('workspace');
      showWorkspaceView('overview');
    } else {
      showView('auth');
    }
  });
  document.getElementById('authToLandingLink').addEventListener('click', (e) => {
    e.preventDefault();
    showView('landing');
  });
  
  // Sidebar navigation elements
  document.querySelectorAll('.sidebar-item').forEach(item => {
    item.addEventListener('click', (e) => {
      e.preventDefault();
      const view = item.dataset.view;
      if (view) {
        showWorkspaceView(view);
      }
    });
  });
}

// --- Auth Controllers ---
function setupAuthHandlers() {
  const loginForm = document.getElementById('loginForm');
  loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = document.getElementById('loginEmail').value;
    const password = document.getElementById('loginPassword').value;
    
    // Hide standard login fields and request MFA if state asks
    const mfaBox = document.getElementById('loginMfaBox');
    let mfaCode = null;
    if (mfaBox.style.display === 'block') {
      mfaCode = document.getElementById('loginMfaCode').value;
    }
    
    showLoader(true);
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password, mfa_code: mfaCode })
      });
      const data = await res.json();
      showLoader(false);
      
      if (res.status === 200) {
        if (data.mfa_required) {
          // Show 2FA input
          mfaBox.style.display = 'block';
          showToast('Two-Factor Authentication (2FA) Required', 'warning');
        } else {
          State.user = data.user;
          updateUserUI();
          showToast('Authentication Successful', 'success');
          showView('workspace');
          showWorkspaceView('overview');
          
          // Reset form
          loginForm.reset();
          mfaBox.style.display = 'none';
        }
      } else {
        showToast(data.message || 'Login Failed', 'danger');
      }
    } catch (err) {
      showLoader(false);
      showToast('Connection failed. Server unavailable.', 'danger');
    }
  });
  
  // Biometric scanner simulator
  const bioScan = document.getElementById('biometricScanner');
  bioScan.addEventListener('click', () => {
    bioScan.classList.add('scanning');
    showToast('Initializing biometric verification profile...', 'info');
    
    setTimeout(() => {
      bioScan.classList.remove('scanning');
      // Autofill fields for quick login simulation
      document.getElementById('loginEmail').value = 'admin@sentraslice.io';
      document.getElementById('loginPassword').value = 'Admin@123456';
      showToast('Biometric signature validated. Press LOGIN.', 'success');
    }, 2000);
  });
  
  // Logout handler
  document.getElementById('logoutBtn').addEventListener('click', async (e) => {
    e.preventDefault();
    try {
      await fetch('/api/auth/logout', { method: 'POST' });
      State.user = null;
      showToast('Logged out successfully', 'info');
      showView('landing');
    } catch (err) {
      console.error(err);
    }
  });
}

function updateUserUI() {
  if (!State.user) return;
  
  // Update header / sidebar values
  const nameEls = document.querySelectorAll('.user-name-placeholder');
  const roleEls = document.querySelectorAll('.user-role-placeholder');
  const avatarEls = document.querySelectorAll('.user-avatar-placeholder');
  
  nameEls.forEach(el => el.innerText = State.user.username);
  roleEls.forEach(el => el.innerText = State.user.role);
  avatarEls.forEach(el => el.innerText = State.user.username.substring(0, 2).toUpperCase());
  
  // Toggle admin/secops capabilities
  const adminSecOpsElements = document.querySelectorAll('.auth-write');
  if (State.user.role === 'Viewer') {
    adminSecOpsElements.forEach(el => el.style.display = 'none');
  } else {
    adminSecOpsElements.forEach(el => el.style.display = 'inline-flex');
  }
  
  const adminOnlyElements = document.querySelectorAll('.admin-only');
  if (State.user.role !== 'Admin') {
    adminOnlyElements.forEach(el => el.style.display = 'none');
  } else {
    adminOnlyElements.forEach(el => el.style.display = 'flex'); // Flex to match sidebar-item layout
  }
}

// --- Notifications System ---
async function fetchNotifications() {
  if (!State.user) return;
  try {
    const res = await fetch('/api/notifications');
    const data = await res.json();
    
    // Check if new critical alert
    const newCount = data.filter(n => !n.is_read).length;
    const badge = document.getElementById('notificationBadge');
    if (badge) {
      badge.style.display = newCount > 0 ? 'block' : 'none';
      badge.innerText = newCount;
    }
    
    // Render dropdown list
    const container = document.getElementById('notificationListDropdown');
    if (container) {
      if (data.length === 0) {
        container.innerHTML = '<div style="padding:16px; text-align:center; color:var(--text-muted)">No warnings detected</div>';
      } else {
        container.innerHTML = data.slice(0, 5).map(n => `
          <div class="notification-dropdown-item ${n.is_read ? '' : 'unread'}">
            <span class="indicator-notif ${n.type.toLowerCase()}"></span>
            <div class="notif-drop-content">
              <h6>${n.title}</h6>
              <p>${n.message}</p>
            </div>
          </div>
        `).join('');
      }
    }
  } catch (err) {
    console.error('Error fetching notifications:', err);
  }
}

// Toast triggers
function showToast(message, type = 'info') {
  const container = document.getElementById('toastContainer');
  if (!container) return;
  
  const toast = document.createElement('div');
  toast.className = `toast-notif ${type}`;
  
  const iconMap = {
    success: 'fa-check-circle',
    danger: 'fa-exclamation-triangle',
    warning: 'fa-exclamation-circle',
    info: 'fa-info-circle'
  };
  
  toast.innerHTML = `
    <i class="fas ${iconMap[type] || 'fa-info-circle'}"></i>
    <span>${message}</span>
  `;
  
  container.appendChild(toast);
  
  // Animate slide in
  setTimeout(() => toast.classList.add('visible'), 50);
  
  // Remove after 4s
  setTimeout(() => {
    toast.classList.remove('visible');
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

// System overlay spinner
function showLoader(visible) {
  const loader = document.getElementById('systemLoaderOverlay');
  if (loader) {
    loader.style.display = visible ? 'flex' : 'none';
  }
}

// --- Fetch Dashboard Summary ---
async function fetchDashboardData() {
  if (!State.user) return;
  try {
    const res = await fetch('/api/analytics');
    const data = await res.json();
    
    // Update summary values
    document.getElementById('metricCpu').innerText = `${data.system_status.cpu_usage}%`;
    document.getElementById('metricMemory').innerText = `${data.system_status.memory_usage}%`;
    
    // Refresh slices list (and update topology)
    const sliceRes = await fetch('/api/slices');
    const slices = await sliceRes.json();
    State.slices = slices;
    
    document.getElementById('metricTotalSlices').innerText = slices.length;
    document.getElementById('metricActiveSlices').innerText = slices.filter(s => s.status === 'active').length;
    
    // Calculate total critical metrics
    let threatCount = 0;
    let criticalCount = 0;
    let worstScore = 100;
    
    slices.forEach(s => {
      worstScore = Math.min(worstScore, s.health_score);
      if (s.risk_level === 'High' || s.risk_level === 'Critical') {
        criticalCount++;
      }
    });
    
    // Fetch active vulnerabilities
    const vulnRes = await fetch('/api/vulnerabilities');
    const vulns = await vulnRes.json();
    threatCount = vulns.length;
    
    document.getElementById('metricThreatCount').innerText = threatCount;
    document.getElementById('metricCriticalThreats').innerText = criticalCount;
    document.getElementById('metricSecurityScore').innerText = `${worstScore}%`;
    
    // Render health progress ring
    const circle = document.getElementById('radialHealthProgress');
    if (circle) {
      const radius = circle.r.baseVal.value;
      const circumference = radius * 2 * Math.PI;
      const offset = circumference - (worstScore / 100) * circumference;
      circle.style.strokeDasharray = circumference;
      circle.style.strokeDashoffset = offset;
      
      // Update score display color
      const scoreText = document.getElementById('metricSecurityScore');
      if (worstScore >= 85) scoreText.style.color = 'var(--color-success)';
      else if (worstScore >= 65) scoreText.style.color = 'var(--color-warning)';
      else scoreText.style.color = 'var(--color-danger)';
    }
    
    // Fetch notifications
    const notificationsRes = await fetch('/api/notifications');
    const notifications = await notificationsRes.json();
    
    // Render threat timeline feed
    const container = document.getElementById('dashboardRecentThreats');
    if (container) {
      container.innerHTML = notifications.slice(0, 4).map(n => `
        <div class="feed-item">
          <div class="feed-badge ${n.type === 'Critical' ? 'danger' : 'info'}">
            <i class="fas ${n.type === 'Critical' ? 'fa-shield-alt' : 'fa-info-circle'}"></i>
          </div>
          <div class="feed-content">
            <div class="feed-title">${n.title}</div>
            <div class="feed-time">${n.message}</div>
          </div>
        </div>
      `).join('');
    }
    
    // Update topology map canvas if function exists
    if (window.drawTopologyMap) {
      window.drawTopologyMap(slices, vulns);
    }
    
    // Render summary charts if function exists
    if (window.renderDashboardCharts) {
      window.renderDashboardCharts(data);
    }
    
  } catch (err) {
    console.error('Error fetching dashboard summary:', err);
  }
}

// Global modal triggers
function openModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) {
    modal.classList.add('active-modal');
  }
}

function closeModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) {
    modal.classList.remove('active-modal');
  }
}
