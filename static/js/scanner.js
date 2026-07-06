// --- Sentraslice Vulnerability Scan Engine Handler (Vercel Serverless / Polling Mode) ---

let scanPollInterval = null;

window.initScannerView = async function() {
  const select = document.getElementById('scanSliceSelect');
  if (!select) return;
  
  // Populate slice choices
  try {
    const res = await fetch('/api/slices');
    const slices = await res.json();
    
    select.innerHTML = slices.map(s => `
      <option value="${s.id}">${s.name} (${s.slice_type} - Score: ${s.health_score}%)</option>
    `).join('');
  } catch (err) {
    console.error('Error fetching slices for scanner selection:', err);
  }
};

window.startVulnerabilityScan = async function() {
  const select = document.getElementById('scanSliceSelect');
  if (!select) return;
  
  const sliceId = select.value;
  if (!sliceId) {
    showToast('Please select a target slice to scan', 'warning');
    return;
  }
  
  // Reset scan layout
  resetScanUI();
  
  try {
    const res = await fetch('/api/scan/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ slice_id: parseInt(sliceId) })
    });
    const data = await res.json();
    
    if (res.status === 201 || res.status === 200) {
      State.currentAssessmentId = data.assessment.id;
      showToast('Assessment Scan Initiated', 'success');
      
      // Toggle button states
      document.getElementById('startScanBtn').disabled = true;
      document.getElementById('scanLoaderText').innerText = 'SCANNING IN PROGRESS...';
      
      // Start polling for real-time logs
      if (scanPollInterval) clearInterval(scanPollInterval);
      scanPollInterval = setInterval(() => pollScanStatus(data.assessment.id), 800);
      
    } else {
      showToast(data.message || 'Scan failed to start', 'danger');
    }
  } catch (err) {
    showToast('Network error, scanner offline', 'danger');
  }
};

async function pollScanStatus(assessmentId) {
  try {
    const res = await fetch(`/api/scan/status?assessment_id=${assessmentId}`);
    if (res.status === 404) {
      clearInterval(scanPollInterval);
      return;
    }
    const data = await res.json();
    
    // Update progress ring and indicators
    updateScanProgressRing(data.progress);
    updateIndicators(data.progress);
    
    // Append logs
    const terminal = document.getElementById('scanTerminalLog');
    if (terminal) {
      terminal.innerHTML = '<div class="terminal-line">[INFO] Initializing assessment scanner console...</div>';
      data.logs.forEach(log => {
        let cls = '';
        if (log.message.includes('[WARN]')) cls = 'warn';
        if (log.message.includes('[ERROR]')) cls = 'error';
        if (log.message.includes('concluded') || log.message.includes('completed')) cls = 'success';
        
        terminal.innerHTML += `<div class="terminal-line ${cls}">[${log.timestamp}] ${log.message}</div>`;
      });
      terminal.scrollTop = terminal.scrollHeight;
    }
    
    if (data.status === 'completed') {
      clearInterval(scanPollInterval);
      document.getElementById('startScanBtn').disabled = false;
      document.getElementById('scanLoaderText').innerText = 'START VULNERABILITY SCAN';
      
      showToast(`Scan Completed. Discovered ${data.threat_count} threats.`, data.threat_count > 0 ? 'warning' : 'success');
      
      // Auto-refresh main dashboard to reflect new threats & scores
      fetchDashboardData();
    }
    
  } catch (err) {
    console.error('Error polling scan status:', err);
  }
}

function resetScanUI() {
  // Clear logs
  const terminal = document.getElementById('scanTerminalLog');
  if (terminal) terminal.innerHTML = '<div class="terminal-line">[INFO] Initializing assessment scanner console...</div>';
  
  // Reset check indicators
  document.querySelectorAll('.scan-indicator-item').forEach(el => {
    el.className = 'scan-indicator-item pending';
    const icon = el.querySelector('i');
    if (icon) icon.className = 'far fa-circle';
  });
  
  // Reset progress circle
  updateScanProgressRing(0);
}

function updateScanProgressRing(progress) {
  const valueText = document.getElementById('scanRadialProgressValue');
  if (valueText) valueText.innerText = `${progress}%`;
  
  const circle = document.getElementById('scanRadialStrokeOffset');
  if (circle) {
    const radius = circle.r.baseVal.value;
    const circumference = radius * 2 * Math.PI;
    const offset = circumference - (progress / 100) * circumference;
    circle.style.strokeDasharray = circumference;
    circle.style.strokeDashoffset = offset;
  }
}

function updateIndicators(progress) {
  // Mapping percentage ranges to checklist status values
  const indicatorMapping = [
    { id: 'ind_auth', min: 10 },
    { id: 'ind_enc', min: 20 },
    { id: 'ind_api', min: 30 },
    { id: 'ind_firewall', min: 40 },
    { id: 'ind_isolation', min: 50 },
    { id: 'ind_ports', min: 60 },
    { id: 'ind_soft', min: 70 },
    { id: 'ind_iam', min: 80 },
    { id: 'ind_certs', min: 90 },
    { id: 'ind_config', min: 100 }
  ];
  
  indicatorMapping.forEach((ind, index) => {
    const el = document.getElementById(ind.id);
    if (!el) return;
    
    const icon = el.querySelector('i');
    
    if (progress >= ind.min) {
      el.className = 'scan-indicator-item completed';
      if (icon) icon.className = 'fas fa-check-circle';
    } else if (progress >= (index > 0 ? indicatorMapping[index-1].min : 0)) {
      el.className = 'scan-indicator-item running';
      if (icon) icon.className = 'fas fa-sync-alt';
    } else {
      el.className = 'scan-indicator-item pending';
      if (icon) icon.className = 'far fa-circle';
    }
  });
}
