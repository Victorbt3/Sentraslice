// --- Sentraslice Canvas Visualizers ---

// --- 1. Landing Hero Particle Animation ---
window.initLandingAnimation = function() {
  const canvas = document.getElementById('landingCanvas');
  if (!canvas) return;
  
  const ctx = canvas.getContext('2d');
  let animationId;
  
  // Fit to parent
  function resize() {
    canvas.width = canvas.parentElement.clientWidth;
    canvas.height = canvas.parentElement.clientHeight;
  }
  resize();
  window.addEventListener('resize', resize);
  
  const particles = [];
  const numParticles = 40;
  
  for (let i = 0; i < numParticles; i++) {
    particles.push({
      x: Math.random() * canvas.width,
      y: Math.random() * canvas.height,
      vx: (Math.random() - 0.5) * 0.8,
      vy: (Math.random() - 0.5) * 0.8,
      radius: Math.random() * 3 + 1,
      glow: Math.random() > 0.7
    });
  }
  
  function draw() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    
    // Draw connections
    ctx.strokeStyle = document.body.classList.contains('light-mode') ? 'rgba(0, 87, 255, 0.05)' : 'rgba(0, 194, 255, 0.08)';
    ctx.lineWidth = 1;
    for (let i = 0; i < numParticles; i++) {
      for (let j = i + 1; j < numParticles; j++) {
        const dx = particles[i].x - particles[j].x;
        const dy = particles[i].y - particles[j].y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        
        if (dist < 120) {
          ctx.beginPath();
          ctx.moveTo(particles[i].x, particles[i].y);
          ctx.lineTo(particles[j].x, particles[j].y);
          ctx.stroke();
        }
      }
    }
    
    // Draw nodes
    particles.forEach(p => {
      p.x += p.vx;
      p.y += p.vy;
      
      // Bounce
      if (p.x < 0 || p.x > canvas.width) p.vx *= -1;
      if (p.y < 0 || p.y > canvas.height) p.vy *= -1;
      
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
      
      if (p.glow) {
        ctx.fillStyle = '#00C2FF';
        ctx.shadowColor = '#00C2FF';
        ctx.shadowBlur = 10;
      } else {
        ctx.fillStyle = document.body.classList.contains('light-mode') ? '#0057FF' : '#3b82f6';
        ctx.shadowBlur = 0;
      }
      
      ctx.fill();
    });
    
    ctx.shadowBlur = 0; // reset
    animationId = requestAnimationFrame(draw);
  }
  
  draw();
  
  // Clean up previous loops on re-init
  canvas.cleanup = () => {
    cancelAnimationFrame(animationId);
    window.removeEventListener('resize', resize);
  };
};

// --- 2. Auth Split Page Visual ---
window.initAuthAnimation = function() {
  const canvas = document.getElementById('authCanvas');
  if (!canvas) return;
  
  const ctx = canvas.getContext('2d');
  let animationId;
  
  function resize() {
    canvas.width = canvas.parentElement.clientWidth;
    canvas.height = canvas.parentElement.clientHeight;
  }
  resize();
  window.addEventListener('resize', resize);
  
  let angle = 0;
  
  function draw() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    
    const cx = canvas.width / 2;
    const cy = canvas.height / 2;
    
    // Draw glowing cyber shield outline
    ctx.strokeStyle = 'rgba(0, 194, 255, 0.15)';
    ctx.lineWidth = 2;
    ctx.beginPath();
    ctx.arc(cx, cy, 140, 0, Math.PI * 2);
    ctx.stroke();
    
    // Rotating satellite nodes
    const numNodes = 6;
    for (let i = 0; i < numNodes; i++) {
      const theta = angle + (i * Math.PI * 2) / numNodes;
      const x = cx + Math.cos(theta) * 140;
      const y = cy + Math.sin(theta) * 140;
      
      // Draw connection to center
      ctx.strokeStyle = 'rgba(0, 87, 255, 0.1)';
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.lineTo(x, y);
      ctx.stroke();
      
      // Draw node
      ctx.beginPath();
      ctx.arc(x, y, 6, 0, Math.PI * 2);
      ctx.fillStyle = i % 2 === 0 ? '#00C2FF' : '#0057FF';
      ctx.fill();
    }
    
    // Center node
    ctx.beginPath();
    ctx.arc(cx, cy, 20, 0, Math.PI * 2);
    ctx.fillStyle = '#0f172a';
    ctx.strokeStyle = '#00C2FF';
    ctx.lineWidth = 3;
    ctx.shadowColor = '#00C2FF';
    ctx.shadowBlur = 15;
    ctx.fill();
    ctx.stroke();
    
    // Lock icon text inside center node
    ctx.shadowBlur = 0;
    ctx.fillStyle = '#00C2FF';
    ctx.font = '12px "Font Awesome 5 Free"';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText('\uf023', cx, cy); // Lock unicode
    
    angle += 0.003;
    animationId = requestAnimationFrame(draw);
  }
  
  draw();
  
  canvas.cleanup = () => {
    cancelAnimationFrame(animationId);
    window.removeEventListener('resize', resize);
  };
};

// --- 3. Interactive Dashboard Topology ---
let topologyAnimId;
window.drawTopologyMap = function(slices, vulnerabilities) {
  const canvas = document.getElementById('topologyCanvas');
  if (!canvas) return;
  
  const ctx = canvas.getContext('2d');
  if (canvas.cleanup) canvas.cleanup();
  
  let width = canvas.width = canvas.parentElement.clientWidth;
  let height = canvas.height = canvas.parentElement.clientHeight;
  
  // Resize handler
  function resize() {
    width = canvas.width = canvas.parentElement.clientWidth;
    height = canvas.height = canvas.parentElement.clientHeight;
  }
  window.addEventListener('resize', resize);
  
  // Define central network nodes
  const nodes = {
    core: { id: 'core', label: '5G CORE', x: width / 2, y: height / 2 - 20, r: 24, type: 'core', color: '#0057FF', status: 'secure' },
    ran: { id: 'ran', label: 'gNodeB (RAN)', x: width / 2 - 160, y: height / 2 - 20, r: 16, type: 'ran', color: '#8b5cf6', status: 'secure' },
    user: { id: 'ue', label: 'UE (User Device)', x: width / 2 - 280, y: height / 2 - 80, r: 10, type: 'device', color: '#10b981', status: 'secure' },
    iot: { id: 'iot', label: 'IoT Endpoint', x: width / 2 - 280, y: height / 2 + 40, r: 10, type: 'device', color: '#f59e0b', status: 'secure' }
  };
  
  // Generate slice gateways dynamically based on backend data
  const sliceNodes = [];
  const sliceTypes = ['eMBB', 'URLLC', 'mMTC'];
  
  slices.forEach((s, idx) => {
    // Spread slice gateways vertically on the right side
    const count = slices.length;
    const spacing = 180 / (count + 1);
    const startY = height / 2 - 90;
    
    let color = '#00C2FF';
    if (s.slice_type === 'URLLC') color = '#FF3D57';
    if (s.slice_type === 'mMTC') color = '#FFD100';
    
    sliceNodes.push({
      id: s.id,
      label: s.name,
      x: width / 2 + 140,
      y: startY + (idx + 1) * spacing,
      r: 14,
      type: 'slice',
      slice_type: s.slice_type,
      color: color,
      status: s.health_score < 70 ? 'threatened' : 'secure',
      health: s.health_score,
      risk: s.risk_level
    });
  });
  
  // Particles flowing along links
  const packets = [];
  
  // Click hover state
  let hoveredNode = null;
  
  canvas.addEventListener('mousemove', (e) => {
    const rect = canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;
    
    hoveredNode = null;
    
    // Check main nodes
    Object.values(nodes).forEach(n => {
      const dist = Math.sqrt((n.x - mx)**2 + (n.y - my)**2);
      if (dist < n.r + 5) hoveredNode = n;
    });
    
    // Check slice nodes
    sliceNodes.forEach(n => {
      const dist = Math.sqrt((n.x - mx)**2 + (n.y - my)**2);
      if (dist < n.r + 5) hoveredNode = n;
    });
  });
  
  canvas.addEventListener('click', () => {
    if (hoveredNode && hoveredNode.type === 'slice') {
      showToast(`Selected slice: ${hoveredNode.label} (Health: ${hoveredNode.health}%)`, 'info');
    }
  });
  
  let step = 0;
  
  function draw() {
    ctx.clearRect(0, 0, width, height);
    const isLight = document.body.classList.contains('light-mode');
    
    // --- DRAW CONNECTIONS ---
    ctx.lineWidth = 2;
    
    // 1. RAN to Devices
    ctx.strokeStyle = isLight ? 'rgba(0,0,0,0.06)' : 'rgba(255,255,255,0.05)';
    ctx.beginPath();
    ctx.moveTo(nodes.ran.x, nodes.ran.y);
    ctx.lineTo(nodes.user.x, nodes.user.y);
    ctx.moveTo(nodes.ran.x, nodes.ran.y);
    ctx.lineTo(nodes.iot.x, nodes.iot.y);
    ctx.stroke();
    
    // 2. RAN to CORE
    ctx.strokeStyle = isLight ? 'rgba(0,0,0,0.1)' : 'rgba(255,255,255,0.08)';
    ctx.beginPath();
    ctx.moveTo(nodes.ran.x, nodes.ran.y);
    ctx.lineTo(nodes.core.x, nodes.core.y);
    ctx.stroke();
    
    // 3. CORE to Slices
    sliceNodes.forEach(sn => {
      if (sn.status === 'threatened') {
        // Glowing flashing threat connection
        const alpha = 0.2 + Math.abs(Math.sin(step * 0.1)) * 0.4;
        ctx.strokeStyle = `rgba(255, 61, 87, ${alpha})`;
        ctx.lineWidth = 3;
      } else {
        ctx.strokeStyle = isLight ? 'rgba(0, 87, 255, 0.1)' : 'rgba(0, 194, 255, 0.12)';
        ctx.lineWidth = 2;
      }
      ctx.beginPath();
      ctx.moveTo(nodes.core.x, nodes.core.y);
      ctx.lineTo(sn.x, sn.y);
      ctx.stroke();
    });
    
    // --- SIMULATE PACKETS ---
    if (step % 20 === 0 && sliceNodes.length > 0) {
      // Spawn data packet
      const targetSlice = sliceNodes[Math.floor(Math.random() * sliceNodes.length)];
      
      packets.push({
        path: [nodes.ran, nodes.core, targetSlice],
        nodeIdx: 0,
        progress: 0,
        speed: 0.02,
        color: targetSlice.color
      });
    }
    
    ctx.lineWidth = 1;
    packets.forEach((p, idx) => {
      const fromNode = p.path[p.nodeIdx];
      const toNode = p.path[p.nodeIdx + 1];
      
      if (!toNode) {
        packets.splice(idx, 1);
        return;
      }
      
      p.progress += p.speed;
      if (p.progress >= 1) {
        p.progress = 0;
        p.nodeIdx++;
        return;
      }
      
      const px = fromNode.x + (toNode.x - fromNode.x) * p.progress;
      const py = fromNode.y + (toNode.y - fromNode.y) * p.progress;
      
      ctx.beginPath();
      ctx.arc(px, py, 4, 0, Math.PI * 2);
      ctx.fillStyle = p.color;
      ctx.shadowColor = p.color;
      ctx.shadowBlur = 8;
      ctx.fill();
    });
    ctx.shadowBlur = 0; // reset
    
    // --- DRAW NODES ---
    
    // Draw main static nodes
    Object.values(nodes).forEach(n => {
      // Glow under Core/RAN
      if (n.type === 'core') {
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.r + 10, 0, Math.PI*2);
        ctx.fillStyle = isLight ? 'rgba(0, 87, 255, 0.05)' : 'rgba(0, 87, 255, 0.15)';
        ctx.fill();
      }
      
      ctx.beginPath();
      ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
      ctx.fillStyle = isLight ? '#ffffff' : '#0f172a';
      ctx.strokeStyle = n.color;
      ctx.lineWidth = 3;
      ctx.fill();
      ctx.stroke();
      
      // Label text
      ctx.fillStyle = isLight ? '#000000' : '#ffffff';
      ctx.font = '10px "Inter", sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText(n.label, n.x, n.y - n.r - 8);
    });
    
    // Draw slices
    sliceNodes.forEach(sn => {
      // Pulse background if threatened
      if (sn.status === 'threatened') {
        ctx.beginPath();
        ctx.arc(sn.x, sn.y, sn.r + 12 * Math.abs(Math.sin(step * 0.06)), 0, Math.PI * 2);
        ctx.fillStyle = 'rgba(255, 61, 87, 0.15)';
        ctx.fill();
        
        // Attacker vector line
        ctx.strokeStyle = 'rgba(255, 61, 87, 0.4)';
        ctx.setLineDash([4, 4]);
        ctx.beginPath();
        ctx.moveTo(sn.x, sn.y);
        ctx.lineTo(sn.x + 80, sn.y - 40);
        ctx.stroke();
        ctx.setLineDash([]);
        
        // Attacker dot
        ctx.beginPath();
        ctx.arc(sn.x + 80, sn.y - 40, 5, 0, Math.PI*2);
        ctx.fillStyle = '#FF3D57';
        ctx.fill();
      }
      
      ctx.beginPath();
      ctx.arc(sn.x, sn.y, sn.r, 0, Math.PI * 2);
      ctx.fillStyle = isLight ? '#ffffff' : '#0f172a';
      ctx.strokeStyle = sn.color;
      ctx.lineWidth = 3;
      ctx.fill();
      ctx.stroke();
      
      // Icon inside slice nodes
      ctx.fillStyle = sn.color;
      ctx.font = '8px "Font Awesome 5 Free"';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      let icon = '\uf109'; // desktop laptop
      if (sn.slice_type === 'URLLC') icon = '\uf0f1'; // stethoscope/heartbeat
      if (sn.slice_type === 'mMTC') icon = '\uf1b9'; // car/IoT
      ctx.fillText(icon, sn.x, sn.y);
      
      // Label text
      ctx.fillStyle = isLight ? '#000000' : '#ffffff';
      ctx.font = '10px "Inter", sans-serif';
      ctx.textAlign = 'left';
      ctx.textBaseline = 'middle';
      ctx.fillText(sn.label, sn.x + sn.r + 8, sn.y);
    });
    
    // Draw tooltip for hovered node
    if (hoveredNode) {
      ctx.fillStyle = 'rgba(15, 23, 42, 0.95)';
      ctx.strokeStyle = hoveredNode.color;
      ctx.lineWidth = 1;
      
      const tx = hoveredNode.x + 20;
      const ty = hoveredNode.y - 40;
      const tw = 160;
      const th = 60;
      
      ctx.beginPath();
      ctx.roundRect(tx, ty, tw, th, 6);
      ctx.fill();
      ctx.stroke();
      
      ctx.fillStyle = '#ffffff';
      ctx.font = 'bold 11px "Inter", sans-serif';
      ctx.textAlign = 'left';
      ctx.fillText(hoveredNode.label, tx + 10, ty + 18);
      
      ctx.font = '10px "Inter", sans-serif';
      ctx.fillStyle = '#94a3b8';
      
      if (hoveredNode.type === 'slice') {
        ctx.fillText(`Slice Type: ${hoveredNode.slice_type}`, tx + 10, ty + 34);
        ctx.fillText(`Score: ${hoveredNode.health}% | Risk: ${hoveredNode.risk}`, tx + 10, ty + 48);
      } else {
        ctx.fillText(`Status: Operational`, tx + 10, ty + 34);
        ctx.fillText(`Node Type: Core Infrastructure`, tx + 10, ty + 48);
      }
    }
    
    step++;
    topologyAnimId = requestAnimationFrame(draw);
  }
  
  draw();
  
  canvas.cleanup = () => {
    cancelAnimationFrame(topologyAnimId);
    window.removeEventListener('resize', resize);
  };
};
