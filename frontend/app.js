// app.js
const API_BASE = 'http://localhost:8000/api/v1';

// DOM Elements
const form = document.getElementById('investigate-form');
const walletInput = document.getElementById('wallet-input');
const submitBtn = document.getElementById('submit-btn');
const submitSpinner = document.getElementById('submit-spinner');
const btnText = submitBtn.querySelector('span');

const progressSection = document.getElementById('progress-section');
const progressBar = document.getElementById('progress-bar');
const progressPercentage = document.getElementById('progress-percentage');
const progressLogs = document.getElementById('progress-logs');

const resultsSection = document.getElementById('results-section');
const riskScore = document.getElementById('risk-score');
const riskLevel = document.getElementById('risk-level');
const gaugeValue = document.getElementById('gauge-value');
const rugpullVerdict = document.getElementById('rugpull-verdict');
const reportTitle = document.getElementById('report-title');
const walletDisplay = document.getElementById('wallet-address-display');
const reportSummary = document.getElementById('report-summary');
const findingsGrid = document.getElementById('findings-grid');
const findingCount = document.getElementById('finding-count');
const noFindings = document.getElementById('no-findings');
const recommendationsList = document.getElementById('recommendations-list');
const apiStatus = document.getElementById('api-status');

// On Load: Check API Health
async function checkApiStatus() {
    try {
        const res = await fetch(`${API_BASE.replace('/api/v1', '')}/health`);
        if (res.ok) {
            apiStatus.textContent = 'API Online';
            apiStatus.classList.add('online');
        }
    } catch (e) {
        console.warn('API Health Check failed', e);
    }
}
checkApiStatus();

// Form Submit Handler
form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const wallet = walletInput.value.trim().toLowerCase();
    
    if (!/^0x[a-f0-9]{40}$/.test(wallet)) {
        alert('Invalid Ethereum address format');
        return;
    }

    startLoadingState();
    
    try {
        // Start Investigation
        addLog('Connecting to backend...');
        const initRes = await fetch(`${API_BASE}/investigate`, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'X-API-Key': 'dev-api-key-change-in-production'
            },
            body: JSON.stringify({ wallet_address: wallet, force_refresh: true })
        });
        
        if (!initRes.ok) throw new Error(`HTTP error! status: ${initRes.status}`);
        const initData = await initRes.json();
        const investigationId = initData.investigation_id;
        addLog(`Investigation started (ID: ${investigationId})`);
        
        // Poll Status
        pollStatus(investigationId);
        
    } catch (error) {
        addLog(`Error: ${error.message}`, true);
        stopLoadingState();
    }
});

// Polling Logic
async function pollStatus(investigationId) {
    let attempts = 0;
    const maxAttempts = 120; // 2 minutes max
    
    const interval = setInterval(async () => {
        try {
            const res = await fetch(`${API_BASE}/investigate/${investigationId}`, {
                headers: { 'X-API-Key': 'dev-api-key-change-in-production' }
            });
            if (!res.ok) throw new Error('Failed to fetch status');
            
            const data = await res.json();
            
            // Update progress (rough estimation based on typical flow)
            let currentPct = parseInt(progressPercentage.textContent);
            if (currentPct < 90 && data.status === 'RUNNING') {
                updateProgress(currentPct + 5);
            }
            
            if (data.status === 'COMPLETE') {
                clearInterval(interval);
                addLog('Investigation complete! Fetching report...');
                updateProgress(100);
                setTimeout(() => fetchReport(investigationId), 500);
            } else if (data.status === 'FAILED') {
                clearInterval(interval);
                addLog('Investigation failed on backend.', true);
                stopLoadingState();
            }
            
            attempts++;
            if (attempts >= maxAttempts) {
                clearInterval(interval);
                addLog('Polling timeout reached.', true);
                stopLoadingState();
            }
            
        } catch (error) {
            console.error('Polling error', error);
        }
    }, 2000);
}

// Fetch Final Report
async function fetchReport(investigationId) {
    try {
        const res = await fetch(`${API_BASE}/report/${investigationId}`, {
            headers: { 'X-API-Key': 'dev-api-key-change-in-production' }
        });
        if (!res.ok) throw new Error('Failed to fetch report');
        
        const data = await res.json();
        renderResults(data);
        stopLoadingState();
        
        // Hide progress, show results
        progressSection.classList.add('hidden');
        resultsSection.classList.remove('hidden');
        
    } catch (error) {
        addLog(`Error fetching report: ${error.message}`, true);
        stopLoadingState();
    }
}

// Render Results to DOM
function renderResults(report) {
    // Top Row
    const score = report.risk_score;
    riskScore.textContent = score;
    walletDisplay.textContent = report.wallet_address;
    reportTitle.textContent = report.title || 'Forensic Analysis Report';
    reportSummary.textContent = report.summary || 'No summary generated.';
    
    // Risk Level & Colors
    const level = report.risk_level;
    riskLevel.textContent = level;
    
    // Reset Classes
    riskScore.className = 'score-number';
    riskLevel.className = 'risk-level';
    gaugeValue.className = 'gauge-value';
    
    let colorClass = '';
    if (level === 'LOW') colorClass = 'is-low';
    else if (level === 'MEDIUM') colorClass = 'is-medium';
    else if (level === 'HIGH') colorClass = 'is-high';
    else if (level === 'CRITICAL') colorClass = 'is-critical';
    
    if (colorClass) {
        riskScore.classList.add(colorClass);
        riskLevel.classList.add(colorClass);
        gaugeValue.classList.add(colorClass);
    }
    
    // Animate Gauge (Max length is 125.6)
    // Offset = length - (length * (score / 100))
    const offset = 125.6 - (125.6 * (score / 100));
    gaugeValue.style.strokeDashoffset = offset;
    
    // Verdict (if rugpull engine ran)
    if (report.forensic_findings && report.forensic_findings.length > 0) {
        rugpullVerdict.textContent = "Findings Detected";
    } else {
        rugpullVerdict.textContent = "No Rule Violations";
    }

    // Findings
    findingsGrid.innerHTML = '';
    const findings = report.forensic_findings || [];
    findingCount.textContent = findings.length;
    
    if (findings.length === 0) {
        noFindings.classList.remove('hidden');
    } else {
        noFindings.classList.add('hidden');
        findings.forEach(f => {
            const card = document.createElement('div');
            card.className = 'finding-card';
            card.setAttribute('data-severity', f.severity);
            
            card.innerHTML = `
                <div class="finding-header">
                    <div class="finding-title">${f.rule_id || f.title}</div>
                    <div class="finding-severity">${f.severity}</div>
                </div>
                <div class="finding-desc">${f.description}</div>
                ${f.reasoning ? `<div class="finding-reasoning"><strong>Context:</strong> ${f.reasoning}</div>` : ''}
            `;
            findingsGrid.appendChild(card);
        });
    }
    
    // Recommendations
    recommendationsList.innerHTML = '';
    const recs = report.recommendations || [];
    if (recs.length === 0) {
        recommendationsList.innerHTML = '<li>No specific recommendations.</li>';
    } else {
        recs.forEach(r => {
            const li = document.createElement('li');
            li.textContent = r;
            recommendationsList.appendChild(li);
        });
    }
}

// UI Helpers
function startLoadingState() {
    submitBtn.disabled = true;
    btnText.textContent = 'Analyzing...';
    submitSpinner.classList.remove('hidden');
    
    resultsSection.classList.add('hidden');
    progressSection.classList.remove('hidden');
    
    progressLogs.innerHTML = '';
    updateProgress(10); // Start at 10%
}

function stopLoadingState() {
    submitBtn.disabled = false;
    btnText.textContent = 'Analyze';
    submitSpinner.classList.add('hidden');
}

function updateProgress(pct) {
    if (pct > 100) pct = 100;
    progressBar.style.width = `${pct}%`;
    progressPercentage.textContent = `${pct}%`;
}

function addLog(msg, isError = false) {
    const d = new Date();
    const time = `${d.getHours().toString().padStart(2, '0')}:${d.getMinutes().toString().padStart(2, '0')}:${d.getSeconds().toString().padStart(2, '0')}`;
    
    const el = document.createElement('div');
    el.className = 'log-entry';
    el.innerHTML = `<span class="timestamp">[${time}]</span> <span class="${isError ? 'text-red' : 'info'}">${msg}</span>`;
    
    progressLogs.appendChild(el);
    progressLogs.scrollTop = progressLogs.scrollHeight;
}
