// --- Sentraslice Analytics Charts & Vectors Map ---

let dashboardCharts = {};

window.renderDashboardCharts = function(data) {
  // Destroy existing charts to prevent rendering artifacts on updates
  if (dashboardCharts.riskTrend) dashboardCharts.riskTrend.destroy();
  if (dashboardCharts.threatDist) dashboardCharts.threatDist.destroy();
  
  const ctxTrend = document.getElementById('riskTrendChart');
  const ctxDist = document.getElementById('threatDistributionChart');
  
  if (!ctxTrend || !ctxDist) return;
  
  const isLight = document.body.classList.contains('light-mode');
  const gridColor = isLight ? 'rgba(0,0,0,0.06)' : 'rgba(255,255,255,0.05)';
  const textColor = isLight ? '#475569' : '#94a3b8';
  
  // 1. Risk Trend Chart (Line)
  dashboardCharts.riskTrend = new Chart(ctxTrend.getContext('2d'), {
    type: 'line',
    data: {
      labels: data.risk_trend.labels,
      datasets: [{
        label: 'Threat Density Index (%)',
        data: data.risk_trend.data,
        borderColor: '#00C2FF',
        backgroundColor: 'rgba(0, 194, 255, 0.08)',
        fill: true,
        tension: 0.4,
        borderWidth: 2,
        pointBackgroundColor: '#00C2FF'
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false }
      },
      scales: {
        x: { grid: { color: gridColor }, ticks: { color: textColor } },
        y: { grid: { color: gridColor }, ticks: { color: textColor }, min: 0, max: 100 }
      }
    }
  });
  
  // 2. Threat Distribution (Doughnut)
  const dist = data.threat_distribution;
  dashboardCharts.threatDist = new Chart(ctxDist.getContext('2d'), {
    type: 'doughnut',
    data: {
      labels: ['Critical', 'High', 'Medium', 'Low'],
      datasets: [{
        data: [dist.Critical, dist.High, dist.Medium, dist.Low],
        backgroundColor: ['#FF3D57', '#FFB300', '#0057FF', '#00C853'],
        borderWidth: isLight ? 2 : 0,
        borderColor: isLight ? '#ffffff' : 'transparent'
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'right',
          labels: { color: textColor, font: { family: 'Inter', size: 11 } }
        }
      },
      cutout: '65%'
    }
  });
};

// --- Analytics Tab Specific Charts & Attack Vectors ---
let analyticsCharts = {};

window.fetchAnalytics = async function() {
  try {
    const res = await fetch('/api/analytics');
    const data = await res.json();
    
    // Render Dashboard widgets
    window.renderDashboardCharts(data);
    
    // Destroy previous analytics charts
    if (analyticsCharts.slicePerf) analyticsCharts.slicePerf.destroy();
    if (analyticsCharts.sysResource) analyticsCharts.sysResource.destroy();
    
    const ctxPerf = document.getElementById('slicePerfChart');
    const ctxRes = document.getElementById('systemResourcesChart');
    
    if (!ctxPerf || !ctxRes) return;
    
    const isLight = document.body.classList.contains('light-mode');
    const gridColor = isLight ? 'rgba(0,0,0,0.06)' : 'rgba(255,255,255,0.05)';
    const textColor = isLight ? '#475569' : '#94a3b8';
    
    // 3. Slice Performance Chart (Bar)
    const sliceNames = Object.keys(data.slice_scores);
    const sliceScores = Object.values(data.slice_scores);
    
    analyticsCharts.slicePerf = new Chart(ctxPerf.getContext('2d'), {
      type: 'bar',
      data: {
        labels: sliceNames,
        datasets: [{
          label: 'Health Rating',
          data: sliceScores,
          backgroundColor: sliceScores.map(score => {
            if (score >= 85) return '#00C853';
            if (score >= 65) return '#FFB300';
            return '#FF3D57';
          }),
          borderRadius: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { display: false }, ticks: { color: textColor } },
          y: { grid: { color: gridColor }, ticks: { color: textColor }, min: 0, max: 100 }
        }
      }
    });
    
    // 4. System Resource Monitor (Line)
    analyticsCharts.sysResource = new Chart(ctxRes.getContext('2d'), {
      type: 'line',
      data: {
        labels: ['14:00', '14:10', '14:20', '14:30', '14:40', '14:50', '15:00'],
        datasets: [
          {
            label: 'CPU Usage (%)',
            data: [12, 18, 15, 24, 19, 14, data.system_status.cpu_usage],
            borderColor: '#00C2FF',
            borderWidth: 2,
            pointRadius: 0,
            fill: false,
            tension: 0.3
          },
          {
            label: 'Memory Usage (%)',
            data: [32, 32, 32, 33, 32.5, 32.7, data.system_status.memory_usage],
            borderColor: '#8b5cf6',
            borderWidth: 2,
            pointRadius: 0,
            fill: false,
            tension: 0.3
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'top',
            labels: { color: textColor }
          }
        },
        scales: {
          x: { grid: { color: gridColor }, ticks: { color: textColor } },
          y: { grid: { color: gridColor }, ticks: { color: textColor }, min: 0, max: 100 }
        }
      }
    });
    
    // Draw Threat Heatmap Vector coordinates
    drawThreatWorldMap(data.attack_sources);
    
  } catch (err) {
    console.error('Error fetching analytics charts:', err);
  }
};

// --- Custom HTML5 Canvas Attacker World Map ---
let worldMapAnimId;
function drawThreatWorldMap(sources) {
  const canvas = document.getElementById('worldMapCanvas');
  if (!canvas) return;
  
  const ctx = canvas.getContext('2d');
  if (canvas.cleanup) canvas.cleanup();
  
  let width = canvas.width = canvas.parentElement.clientWidth;
  let height = canvas.height = canvas.parentElement.clientHeight;
  
  function resize() {
    width = canvas.width = canvas.parentElement.clientWidth;
    height = canvas.height = canvas.parentElement.clientHeight;
  }
  window.addEventListener('resize', resize);
  
  let step = 0;
  
  // Custom mock locations mapped on flat projection coordinate canvas (x: 0-1, y: 0-1)
  // center core target coordinate is NOC center
  const targetX = width * 0.5;
  const targetY = height * 0.55;
  
  const origins = sources.map((s, idx) => {
    // Map latitude/longitude roughly to local width/height
    // standard Mercator projection approximation:
    // lat (90 to -90) -> (0 to 1), lon (-180 to 180) -> (0 to 1)
    const lat = s.coordinates[0];
    const lon = s.coordinates[1];
    
    const x = width * (0.5 + (lon / 360));
    const y = height * (0.5 - (lat / 180));
    
    return {
      name: s.country,
      ip: s.ip,
      x: x,
      y: y,
      blocked: s.threats_blocked,
      phase: idx * (Math.PI / 4)
    };
  });
  
  function draw() {
    ctx.clearRect(0, 0, width, height);
    const isLight = document.body.classList.contains('light-mode');
    
    // Draw grid map matrix background
    ctx.fillStyle = isLight ? 'rgba(0,0,0,0.03)' : 'rgba(255, 255, 255, 0.02)';
    const cols = 40;
    const rows = 20;
    const cw = width / cols;
    const rh = height / rows;
    for (let c = 0; c < cols; c++) {
      for (let r = 0; r < rows; r++) {
        // Draw grid dots
        ctx.beginPath();
        ctx.arc(c * cw + cw/2, r * rh + rh/2, 1.5, 0, Math.PI * 2);
        ctx.fill();
      }
    }
    
    // Draw target NOC node
    ctx.beginPath();
    ctx.arc(targetX, targetY, 8, 0, Math.PI * 2);
    ctx.fillStyle = '#0057FF';
    ctx.strokeStyle = '#00C2FF';
    ctx.lineWidth = 2;
    ctx.fill();
    ctx.stroke();
    
    ctx.fillStyle = isLight ? '#000000' : '#ffffff';
    ctx.font = 'bold 9px "Inter", sans-serif';
    ctx.fillText("NOC CENTER (TARGET)", targetX + 12, targetY + 3);
    
    // Draw origin vector attacks
    origins.forEach(origin => {
      // Draw source dot
      ctx.beginPath();
      ctx.arc(origin.x, origin.y, 4, 0, Math.PI * 2);
      ctx.fillStyle = '#FF3D57';
      ctx.fill();
      
      ctx.fillStyle = isLight ? '#475569' : '#94a3b8';
      ctx.font = '8px "Inter", sans-serif';
      ctx.fillText(`${origin.name} (${origin.ip})`, origin.x + 8, origin.y + 3);
      
      // Draw flying arc connection
      ctx.strokeStyle = 'rgba(255, 61, 87, 0.15)';
      ctx.lineWidth = 1;
      
      ctx.beginPath();
      ctx.moveTo(origin.x, origin.y);
      // quadratic curve
      const ctrlX = (origin.x + targetX) / 2;
      const ctrlY = Math.min(origin.y, targetY) - 50;
      ctx.quadraticCurveTo(ctrlX, ctrlY, targetX, targetY);
      ctx.stroke();
      
      // Drawing particle traversing the arc
      const t = (step * 0.01 + origin.phase) % 1;
      // get point on quadratic Bezier curve
      const mt = 1 - t;
      const px = mt * mt * origin.x + 2 * mt * t * ctrlX + t * t * targetX;
      const py = mt * mt * origin.y + 2 * mt * t * ctrlY + t * t * targetY;
      
      ctx.beginPath();
      ctx.arc(px, py, 3, 0, Math.PI * 2);
      ctx.fillStyle = '#FF3D57';
      ctx.shadowColor = '#FF3D57';
      ctx.shadowBlur = 6;
      ctx.fill();
      ctx.shadowBlur = 0; // reset
    });
    
    step++;
    worldMapAnimId = requestAnimationFrame(draw);
  }
  
  draw();
  
  canvas.cleanup = () => {
    cancelAnimationFrame(worldMapAnimId);
    window.removeEventListener('resize', resize);
  };
}
