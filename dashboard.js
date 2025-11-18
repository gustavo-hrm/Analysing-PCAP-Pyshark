
// === Dashboard JS (Stability v20.3 - DDoS Detection) ===
if (window.__DASHBOARD_ACTIVE__) { console.warn("Dashboard already active — skipping duplicate init."); }
else { window.__DASHBOARD_ACTIVE__ = true; }

if (window.jQuery && window.jQuery.fn) {
  try { $.fn.dataTable.ext.errMode = 'none'; } catch(e) {}
}

const dnsData       = [];
const httpData      = [];
const tlsData       = [];
const tcpData       = [];
const timelineData  = [];

const c2Data        = [];   // compact subset exclusively for the graph
const c2FullData    = [];    // complete heuristic table dataset

const advData       = [];
const beaconData    = [];
const dnstunnelData = [];

// DDoS Detection Data
const ddosData      = [];      // all DDoS detections
const ddosGraphData = []; // DDoS graph subset

// HTTP C2 Detection Data
const httpC2Data    = [];    // HTTP C2 target distribution


// ------------------------------------------------------------
// Table rendering helper
// ------------------------------------------------------------
function renderTableRows(tbody, rows, cols){
  if(!tbody) return;
  tbody.innerHTML = '';
  rows.forEach(r=>{
    const tr = document.createElement('tr');
    cols.forEach(c=>{
      const td = document.createElement('td');
      td.textContent = r[c] !== undefined ? r[c] : '';
      td.title = td.textContent;  // Show full text on hover
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  });
}


// ------------------------------------------------------------
// Canvas preparation
// ------------------------------------------------------------
function prepareCanvas(canvas, fixedHeight){
  if(!canvas) return null;
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  const h = fixedHeight || rect.height || 220;

  canvas.width  = Math.max(1, Math.floor(rect.width * dpr));
  canvas.height = Math.max(1, Math.floor(h * dpr));

  const ctx = canvas.getContext('2d');
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  return ctx;
}


// ------------------------------------------------------------
// Simple bar chart factory
// ------------------------------------------------------------
function createBarChart(id, labels, values, title){
  const el = document.getElementById(id);
  if(!el) return null;
  const ctx = prepareCanvas(el, 220);
  if(!ctx) return null;

  try{
    return new Chart(ctx, {
      type:'bar',
      data:{
        labels:labels.slice(0,50),
        datasets:[{ label:title, data:values.slice(0,50) }]
      },
      options:{
        responsive:false,
        maintainAspectRatio:false,
        animation:false,
        legend:{ display:false }
      }
    });
  }catch(e){
    console.log('chart err', e);
    return null;
  }
}


// ------------------------------------------------------------
// Pivot view (SRC → DST)
// ------------------------------------------------------------
function renderPivot(tbody, data){
  if(!tbody) return;

  const map = {};
  data.forEach(r=>{
    const s = r.SRC_IP || 'unknown';
    const d = r.DST_IP || 'unknown';
    map[s] = map[s] || {};
    map[s][d] = (map[s][d]||0) + (r.COUNT||1);
  });

  const rows = [];
  Object.keys(map).forEach(s=>{
    Object.keys(map[s]).forEach(d=>{
      rows.push({SRC:s, DST:d, COUNT: map[s][d]});
    });
  });

  rows.sort((a,b)=>b.COUNT - a.COUNT);
  renderTableRows(tbody, rows.slice(0,200), ['SRC','DST','COUNT']);
}


// ------------------------------------------------------------
// Render C2 Graph using Cytoscape
// ------------------------------------------------------------
function renderC2Graph(containerId, data){
  if(typeof cytoscape === 'undefined') return;

  const el = document.getElementById(containerId);
  if(!el) return;

  const nodes = {};
  const edges = [];
  const nodeScores = {};  // NEW: Track max score per node

  data.slice(0,500).forEach((r,i)=>{

    // Graph expects SRC_IP and DST_IP
    const s = r.SRC_IP || ('src'+i);
    const d = r.DST_IP || ('dst'+i);
    const score = r.SCORE || 0;

    nodes[s] = (nodes[s]||0) + (r.COUNT||1);
    nodes[d] = (nodes[d]||0) + (r.COUNT||1);

    // Track highest score for each node
    nodeScores[s] = Math.max(nodeScores[s] || 0, score);
    nodeScores[d] = Math.max(nodeScores[d] || 0, score);

    edges.push({
      data:{ id:'e'+i, source:s, target:d, weight:r.COUNT||1, score: score }
    });
  });

  const cy_nodes = Object.keys(nodes).map(n=>({
    data:{ 
      id:n, 
      label: n + '\n[' + (nodeScores[n] || 0) + ']',  // Show IP + score
      weight:nodes[n],
      score: nodeScores[n] || 0
    }
  }));

  // Color nodes by score (red = high threat)
  const getNodeColor = (score) => {
    if (score >= 90) return '#dc2626';  // Red - critical
    if (score >= 75) return '#ea580c';  // Orange - high
    if (score >= 60) return '#f59e0b';  // Yellow - medium
    return '#1976d2';  // Blue - low/info
  };

  el.innerHTML = '';

  try{
    cytoscape({
      container: el,
      elements: {
        nodes: cy_nodes,
        edges: edges
      },
      style:[
        {
          selector:'node',
          style:{
            'label': 'data(label)',
            'width':'mapData(weight,0,100,12,42)',
            'height':'mapData(weight,0,100,12,42)',
            'background-color': function(ele){ return getNodeColor(ele.data('score')); },
            'color':'#fff',
            'text-valign':'center',
            'text-halign':'center',
            'font-size': 9,
            'text-wrap': 'wrap',
            'text-max-width': 80
          }
        },
        {
          selector:'edge',
          style:{
            'width':'mapData(weight,0,100,1,6)',
            'line-color': function(ele){ 
              const score = ele.data('score');
              if (score >= 90) return '#dc2626';
              if (score >= 75) return '#ea580c';
              return '#999';
            },
            'opacity':0.85
          }
        }
      ],
      layout:{ name:'cose', animate:false, nodeRepulsion: 8000 }
    });
  }catch(e){
    console.log('cytoscape err', e);
  }
}


// ------------------------------------------------------------
// Dashboard update
// ------------------------------------------------------------
function updateDashboard(){

  const topN = parseInt(document.getElementById('topN').value || '15');

  const fs = (document.getElementById('filter_src')||{value:''}).value.trim();
  const fd = (document.getElementById('filter_dst')||{value:''}).value.trim();
  const fm = (document.getElementById('filter_dom')||{value:''}).value.trim().toLowerCase();

  const ff = r=>{
    if(fs && r.SRC_IP && !String(r.SRC_IP).includes(fs)) return false;
    if(fd && r.DST_IP && !String(r.DST_IP).includes(fd)) return false;
    if(fm){
      const s = Object.values(r).join(' ').toLowerCase();
      if(!s.includes(fm)) return false;
    }
    return true;
  };

  const dnsSlice  = (dnsData||[]).slice().sort((a,b)=>(b.COUNT||0)-(a.COUNT||0)).slice(0,topN).filter(ff);
  const httpSlice = (httpData||[]).slice().sort((a,b)=>(b.COUNT||0)-(a.COUNT||0)).slice(0,topN).filter(ff);
  const tlsSlice  = (tlsData||[]).slice().sort((a,b)=>(b.COUNT||0)-(a.COUNT||0)).slice(0,topN).filter(ff);

  const tcpSliceFiltered = (tcpData||[]).slice().sort((a,b)=>(b.COUNT||0)-(a.COUNT||0)).slice(0,topN).filter(ff);
  const tcpSliceFull     = (tcpData||[]).slice().sort((a,b)=>(b.COUNT||0)-(a.COUNT||0));

  // ------------------------
  // TABLES
  // ------------------------
  renderTableRows(document.querySelector('#tbl_dns tbody'), dnsSlice, ['DOMAIN','COUNT','PERCENT']);
  renderTableRows(document.querySelector('#tbl_http tbody'), httpSlice, ['DOMAIN','COUNT','PERCENT']);
  renderTableRows(document.querySelector('#tbl_tls tbody'), tlsSlice, ['SNI','JA3','SRC_IP','DST_IP','COUNT','PERCENT']);
  renderTableRows(document.querySelector('#tbl_tcp tbody'), tcpSliceFiltered, ['SRC_IP','DST_IP','FLAGS','COUNT','PERCENT']);

  // FULL C2 table (not filtered)
  renderTableRows(
    document.querySelector('#tbl_c2 tbody'),
    (c2FullData||[]).slice(0,topN),
    ['INDICATOR','TYPE','SCORE','COUNT']
  );

  // Advanced, beacon, DNS tunnel
  renderTableRows(document.querySelector('#tbl_adv tbody'), (advData||[]).slice(0,topN), ['INDICATOR','TYPE','SCORE','COUNT']);
  renderTableRows(document.querySelector('#tbl_beacon tbody'), (beaconData||[]).slice(0,topN), ['INDICATOR','TYPE','SCORE','COUNT']);
  renderTableRows(document.querySelector('#tbl_dnstunnel tbody'), (dnstunnelData||[]).slice(0,topN), ['INDICATOR','TYPE','SCORE','COUNT','NOTES']);
  
  // DDoS Detection table
  const ddosSlice = (ddosData||[]).slice().sort((a,b)=>(b.SCORE||0)-(a.SCORE||0)).slice(0,topN);
  renderTableRows(document.querySelector('#tbl_ddos tbody'), ddosSlice, ['INDICATOR','TYPE','SCORE','COUNT']);

  // HTTP C2 Detection table
  const httpC2Slice = (httpC2Data||[]).slice().sort((a,b)=>(b.SCORE||0)-(a.SCORE||0)).slice(0,topN);
  renderTableRows(document.querySelector('#tbl_http_c2 tbody'), httpC2Slice, 
    ['C2_SERVER','BOT_COUNT','EXTRACTED_IPS','TARGETS_DISTRIBUTED','PAYLOAD_SAMPLE',
     'TARGETS_ATTACKED','CORRELATION_SCORE','TIME_TO_ATTACK','SCORE']);

  // ------------------------
  // PIVOT
  // ------------------------
  renderPivot(document.querySelector('#pivot tbody'), tcpSliceFull);

  // ------------------------
  // C2 GRAPH
  // ------------------------
  let edgesForGraph = (c2Data || []).slice();

  // FIX: Prevent hairball graph
  if(edgesForGraph.length > 150){
    console.warn("C2 graph trimmed to 150 edges for readability.");
    edgesForGraph = edgesForGraph.slice(0,150);
  }

  renderC2Graph('c2graph', edgesForGraph);
  
  // ------------------------
  // DDoS GRAPH
  // ------------------------
  let ddosEdgesForGraph = (ddosGraphData || []).slice();
  if(ddosEdgesForGraph.length > 150){
    console.warn("DDoS graph trimmed to 150 edges for readability.");
    ddosEdgesForGraph = ddosEdgesForGraph.slice(0,150);
  }
  renderC2Graph('ddosgraph', ddosEdgesForGraph);

  // ------------------------
  // CHARTS
  // ------------------------
  if(window._dns) try{ window._dns.destroy(); }catch(e){}
  window._dns = createBarChart('chart_dns', dnsSlice.map(x=>x.DOMAIN||''), dnsSlice.map(x=>x.COUNT||0), 'DNS');

  if(window._http) try{ window._http.destroy(); }catch(e){}
  window._http = createBarChart('chart_http', httpSlice.map(x=>x.DOMAIN||''), httpSlice.map(x=>x.COUNT||0), 'HTTP');

  if(window._tls) try{ window._tls.destroy(); }catch(e){}
  window._tls = createBarChart('chart_tls', tlsSlice.map(x=>x.SNI||''), tlsSlice.map(x=>x.COUNT||0), 'TLS');

  if(window._tcp) try{ window._tcp.destroy(); }catch(e){}
  window._tcp = createBarChart(
    'chart_tcp',
    tcpSliceFiltered.map(x=> (x.SRC_IP||'')+' → '+(x.DST_IP||'')),
    tcpSliceFiltered.map(x=>x.COUNT||0),
    'TCP'
  );

  // Timeline
  try{
    const ctx = prepareCanvas(document.getElementById('chart_timeline'), 220);
    if(ctx){
      window._timeline = new Chart(ctx, {
        type:'line',
        data:{
          labels: timelineData.map(x=>x.label),
          datasets:[{ label:'HTTP/min', data: timelineData.map(x=>x.count) }]
        },
        options:{ responsive:false, animation:false, legend:{ display:false } }
      });
    }
  }catch(e){
    console.log('timeline err', e);
  }

  setTimeout(()=>{ try{ $('.display').DataTable().columns.adjust(false); }catch(e){} }, 80);
}


// ------------------------------------------------------------
// INIT
// ------------------------------------------------------------
document.addEventListener('DOMContentLoaded', function(){

  ['topN','filter_src','filter_dst','filter_dom'].forEach(id=>{
    const el = document.getElementById(id);
    if(el) el.addEventListener('input', updateDashboard);
  });

  document.getElementById('clear_filters')?.addEventListener('click', function(){
    ['filter_src','filter_dst','filter_dom'].forEach(id=>{
      const e = document.getElementById(id);
      if(e) e.value='';
    });
    updateDashboard();
  });

  document.getElementById('darkToggle')?.addEventListener('click', function(){
    document.body.classList.toggle('dark');
    updateDashboard();
  });

  updateDashboard();
});
