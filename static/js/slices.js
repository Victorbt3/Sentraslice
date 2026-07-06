// --- Sentraslice Network Slice Management Controllers ---

window.setupSliceHandlers = function() {
  const form = document.getElementById('sliceModalForm');
  if (form) {
    form.addEventListener('submit', handleSliceSubmit);
  }
  
  // Search and filter triggers
  const filterSearch = document.getElementById('sliceSearchInput');
  const filterType = document.getElementById('sliceTypeFilter');
  const filterStatus = document.getElementById('sliceStatusFilter');
  const filterSort = document.getElementById('sliceSortSelect');
  
  const triggers = [filterSearch, filterType, filterStatus, filterSort];
  triggers.forEach(t => {
    if (t) {
      t.addEventListener('input', () => fetchSlices());
      t.addEventListener('change', () => fetchSlices());
    }
  });
};

window.fetchSlices = async function() {
  if (!State.user) return;
  
  const search = document.getElementById('sliceSearchInput')?.value || '';
  const type = document.getElementById('sliceTypeFilter')?.value || '';
  const status = document.getElementById('sliceStatusFilter')?.value || '';
  const sortBy = document.getElementById('sliceSortSelect')?.value || 'name';
  
  try {
    const res = await fetch(`/api/slices?search=${search}&type=${type}&status=${status}&sort_by=${sortBy}`);
    const slices = await res.json();
    State.slices = slices;
    
    renderSliceGrid(slices);
  } catch (err) {
    console.error('Error fetching slices:', err);
  }
};

function renderSliceGrid(slices) {
  const container = document.getElementById('sliceGridContainer');
  if (!container) return;
  
  if (slices.length === 0) {
    container.innerHTML = `
      <div style="grid-column: 1/-1; text-align: center; padding: 48px;" class="glass-card">
        <i class="fas fa-network-wired" style="font-size: 3rem; color: var(--text-muted); margin-bottom: 16px;"></i>
        <h3>No Slices Found</h3>
        <p style="color: var(--text-muted); margin-top: 8px;">Modify your search filters or create a new slice configurations.</p>
      </div>
    `;
    return;
  }
  
  container.innerHTML = slices.map(s => {
    let riskBadge = 'badge-low';
    if (s.risk_level === 'Medium') riskBadge = 'badge-medium';
    if (s.risk_level === 'High') riskBadge = 'badge-high';
    if (s.risk_level === 'Critical') riskBadge = 'badge-critical';
    
    let typeLabel = s.slice_type;
    let typeDesc = 'Enhanced Mobile Broadband';
    if (s.slice_type === 'URLLC') typeDesc = 'Ultra-Reliable Low-Latency';
    if (s.slice_type === 'mMTC') typeDesc = 'Massive Machine Type IoT';
    
    // Status button action
    const toggleBtnLabel = s.status === 'active' ? 'Pause' : 'Resume';
    const toggleBtnIcon = s.status === 'active' ? 'fa-pause' : 'fa-play';
    
    return `
      <div class="glass-card slice-card interactive">
        <div class="slice-card-header">
          <div class="slice-meta-type">
            <div class="slice-type-icon ${s.slice_type}">
              <i class="fas ${s.slice_type === 'eMBB' ? 'fa-broadcast-tower' : (s.slice_type === 'URLLC' ? 'fa-heartbeat' : 'fa-microchip')}"></i>
            </div>
            <div>
              <h4 style="font-size: 1rem; font-weight: 700;">${s.name}</h4>
              <span style="font-size: 0.75rem; color: var(--text-muted);" title="${typeDesc}">${typeLabel}</span>
            </div>
          </div>
          <span class="badge ${riskBadge}">${s.risk_level}</span>
        </div>
        
        <div class="slice-card-details">
          <div class="slice-metric-item">
            <span class="slice-metric-label">LATENCY</span>
            <span class="slice-metric-value">${s.latency} ms</span>
          </div>
          <div class="slice-metric-item">
            <span class="slice-metric-label">BANDWIDTH</span>
            <span class="slice-metric-value">${s.bandwidth} Gbps</span>
          </div>
          <div class="slice-metric-item">
            <span class="slice-metric-label">FIREWALL</span>
            <span class="slice-metric-value" style="color: ${s.firewall ? 'var(--color-success)' : 'var(--color-danger)'}">
              ${s.firewall ? 'Enabled' : 'Disabled'}
            </span>
          </div>
          <div class="slice-metric-item">
            <span class="slice-metric-label">ENCRYPTION</span>
            <span class="slice-metric-value">${s.encryption}</span>
          </div>
        </div>
        
        <div class="slice-card-footer">
          <div>
            <span style="font-size: 0.75rem; color: var(--text-muted);">Health Score</span>
            <div style="font-size: 1.15rem; font-weight: 700; color: ${s.health_score >= 85 ? 'var(--color-success)' : (s.health_score >= 65 ? 'var(--color-warning)' : 'var(--color-danger)')}">
              ${s.health_score}%
            </div>
          </div>
          <div class="auth-write" style="display: flex; gap: 8px;">
            <button class="btn btn-outline btn-icon" onclick="toggleSlice(${s.id})" title="${toggleBtnLabel} Slice">
              <i class="fas ${toggleBtnIcon}"></i>
            </button>
            <button class="btn btn-outline btn-icon" onclick="openEditSliceModal(${s.id})" title="Edit Config">
              <i class="fas fa-edit"></i>
            </button>
            <button class="btn btn-outline btn-icon" onclick="duplicateSlice(${s.id})" title="Duplicate Slice">
              <i class="fas fa-copy"></i>
            </button>
            <button class="btn btn-outline btn-icon" style="color:var(--color-danger)" onclick="deleteSlice(${s.id})" title="Delete Slice">
              <i class="fas fa-trash-alt"></i>
            </button>
          </div>
        </div>
      </div>
    `;
  }).join('');
  
  // Make sure to hide write actions if user role is Viewer
  if (State.user && State.user.role === 'Viewer') {
    document.querySelectorAll('.auth-write').forEach(el => el.style.display = 'none');
  }
}

// Slice modal operations
window.openCreateSliceModal = function() {
  document.getElementById('sliceModalTitle').innerText = 'Create 5G Network Slice';
  document.getElementById('sliceModalForm').reset();
  document.getElementById('sliceModalId').value = '';
  openModal('sliceFormModal');
};

window.openEditSliceModal = function(sliceId) {
  const s = State.slices.find(slice => slice.id === sliceId);
  if (!s) return;
  
  document.getElementById('sliceModalTitle').innerText = 'Edit Slice Configuration';
  document.getElementById('sliceModalId').value = s.id;
  document.getElementById('sliceName').value = s.name;
  document.getElementById('sliceType').value = s.slice_type;
  document.getElementById('sliceLatency').value = s.latency;
  document.getElementById('sliceBandwidth').value = s.bandwidth;
  document.getElementById('sliceEncryption').value = s.encryption;
  document.getElementById('sliceAuthentication').value = s.authentication;
  document.getElementById('sliceFirewall').checked = s.firewall;
  
  openModal('sliceFormModal');
};

async function handleSliceSubmit(e) {
  e.preventDefault();
  
  const id = document.getElementById('sliceModalId').value;
  const name = document.getElementById('sliceName').value;
  const slice_type = document.getElementById('sliceType').value;
  const latency = parseInt(document.getElementById('sliceLatency').value);
  const bandwidth = parseFloat(document.getElementById('sliceBandwidth').value);
  const encryption = document.getElementById('sliceEncryption').value;
  const authentication = document.getElementById('sliceAuthentication').value;
  const firewall = document.getElementById('sliceFirewall').checked;
  
  const payload = { name, slice_type, latency, bandwidth, encryption, authentication, firewall };
  
  const url = id ? `/api/slices/${id}` : '/api/slices';
  const method = id ? 'PUT' : 'POST';
  
  try {
    const res = await fetch(url, {
      method: method,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    
    const data = await res.json();
    if (res.status === 200 || res.status === 201) {
      showToast(id ? 'Slice configuration updated' : 'Network slice deployed successfully', 'success');
      closeModal('sliceFormModal');
      fetchSlices();
      fetchDashboardData();
    } else {
      showToast(data.message || 'Action failed', 'danger');
    }
  } catch (err) {
    showToast('Network error, action failed', 'danger');
  }
}

window.toggleSlice = async function(sliceId) {
  try {
    const res = await fetch(`/api/slices/${sliceId}/toggle`, { method: 'POST' });
    if (res.status === 200) {
      showToast('Slice status toggled', 'success');
      fetchSlices();
      fetchDashboardData();
    }
  } catch (err) {
    console.error(err);
  }
};

window.duplicateSlice = async function(sliceId) {
  try {
    const res = await fetch(`/api/slices/${sliceId}/duplicate`, { method: 'POST' });
    if (res.status === 201) {
      showToast('Slice duplicated successfully', 'success');
      fetchSlices();
      fetchDashboardData();
    }
  } catch (err) {
    console.error(err);
  }
};

window.deleteSlice = async function(sliceId) {
  if (!confirm('Are you sure you want to decommission this network slice? This will remove all logs and reports.')) return;
  
  try {
    const res = await fetch(`/api/slices/${sliceId}`, { method: 'DELETE' });
    if (res.status === 200) {
      showToast('Network slice decommissioned', 'info');
      fetchSlices();
      fetchDashboardData();
    }
  } catch (err) {
    console.error(err);
  }
};
