// API endpoints
const API = {
    networkInfo: '/api/network-info',
    scanStart: '/api/scan/start',
    scanProgress: '/api/scan/progress',
    scanResults: '/api/scan/results'
};

// DOM elements
const startScanBtn = document.getElementById('start-scan-btn');
const scanTarget = document.getElementById('scan-target');
const scanType = document.getElementById('scan-type');
const progressCard = document.getElementById('progress-card');
const progressStep = document.getElementById('progress-step');
const progressFill = document.getElementById('progress-fill');
const progressPercent = document.getElementById('progress-percent');
const resultsSection = document.getElementById('results-section');
const hostResults = document.getElementById('host-results');

// Stats elements
const statHosts = document.getElementById('stat-hosts');
const statPorts = document.getElementById('stat-ports');
const statVulns = document.getElementById('stat-vulns');
const statServices = document.getElementById('stat-services');

// State
let scanInterval = null;

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    loadNetworkInfo();
    setupEventListeners();
});

// Load network information
async function loadNetworkInfo() {
    try {
        const response = await fetch(API.networkInfo);
        const data = await response.json();
        
        if (data.success) {
            document.getElementById('local-ip').textContent = data.local_ip;
            document.getElementById('network-range').textContent = data.network_range;
        }
    } catch (error) {
        console.error('Error loading network info:', error);
    }
}

// Setup event listeners
function setupEventListeners() {
    startScanBtn.addEventListener('click', startScan);
}

// Start scan
async function startScan() {
    const target = scanTarget.value.trim();
    const type = scanType.value;
    
    try {
        startScanBtn.disabled = true;
        startScanBtn.textContent = '⏳ Scanning...';
        
        const response = await fetch(API.scanStart, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                target: target,
                scan_type: type
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            // Show progress card
            progressCard.classList.remove('hidden');
            resultsSection.classList.add('hidden');
            
            // Start polling for progress
            startProgressPolling();
        } else {
            alert('Error: ' + data.error);
            resetScanButton();
        }
    } catch (error) {
        console.error('Error starting scan:', error);
        alert('Failed to start scan');
        resetScanButton();
    }
}

// Poll for scan progress
function startProgressPolling() {
    scanInterval = setInterval(async () => {
        try {
            const response = await fetch(API.scanProgress);
            const data = await response.json();
            
            // Update progress
            progressStep.textContent = data.current_step;
            progressFill.style.width = data.progress + '%';
            progressPercent.textContent = data.progress + '%';
            
            // Check if complete
            if (data.status === 'complete') {
                clearInterval(scanInterval);
                loadResults();
            } else if (data.status === 'error') {
                clearInterval(scanInterval);
                alert('Scan failed: ' + data.current_step);
                resetScanButton();
            }
        } catch (error) {
            console.error('Error polling progress:', error);
        }
    }, 1000);
}

// Load scan results
async function loadResults() {
    try {
        const response = await fetch(API.scanResults);
        const data = await response.json();
        
        if (data.success) {
            displayResults(data.results);
            resetScanButton();
            progressCard.classList.add('hidden');
        }
    } catch (error) {
        console.error('Error loading results:', error);
    }
}

// Display scan results
function displayResults(results) {
    // Calculate statistics
    const hosts = results.hosts || [];
    const totalPorts = hosts.reduce((sum, host) => sum + host.ports.length, 0);
    const totalVulns = hosts.reduce((sum, host) => sum + host.vulnerabilities.length, 0);
    const totalServices = hosts.reduce((sum, host) => sum + host.services.length, 0);
    
    // Update stats
    statHosts.textContent = hosts.length;
    statPorts.textContent = totalPorts;
    statVulns.textContent = totalVulns;
    statServices.textContent = totalServices;
    
    // Display hosts
    hostResults.innerHTML = '';
    hosts.forEach(host => {
        const hostCard = createHostCard(host);
        hostResults.appendChild(hostCard);
    });
    
    // Show results section
    resultsSection.classList.remove('hidden');
}

// Create host card
function createHostCard(host) {
    const card = document.createElement('div');
    card.className = 'host-card';
    
    const osInfo = host.os.os || 'Unknown';
    
    card.innerHTML = `
        <div class="host-header">
            <div>
                <div class="host-title">${host.ip}</div>
                <div class="host-os">🖥️ ${host.hostname} | OS: ${osInfo}</div>
            </div>
            <div>
                <span class="badge">${host.ports.length} ports open</span>
            </div>
        </div>
        
        <div class="host-details">
            <div class="detail-section">
                <h4>🔓 Open Ports</h4>
                <ul class="port-list">
                    ${host.ports.map(port => `
                        <li class="port-item">${port.port}/tcp - ${port.service}</li>
                    `).join('')}
                    ${host.ports.length === 0 ? '<li class="port-item">No open ports</li>' : ''}
                </ul>
            </div>
            
            <div class="detail-section">
                <h4>🎯 Services</h4>
                <ul class="service-list">
                    ${host.services.map(service => `
                        <li class="service-item">
                            ${service.port}: ${service.service} ${service.version || ''}
                        </li>
                    `).join('')}
                    ${host.services.length === 0 ? '<li class="service-item">No services detected</li>' : ''}
                </ul>
            </div>
            
            <div class="detail-section">
                <h4>⚠️ Vulnerabilities</h4>
                <ul class="vuln-list">
                    ${host.vulnerabilities.map(vuln => `
                        <li class="vuln-item ${vuln.severity.toLowerCase()}">
                            <div class="vuln-severity">[${vuln.severity}] ${vuln.type}</div>
                            <div class="vuln-description">${vuln.description}</div>
                            ${vuln.cve !== 'N/A' ? `<div class="vuln-cve">CVE: ${vuln.cve}</div>` : ''}
                        </li>
                    `).join('')}
                    ${host.vulnerabilities.length === 0 ? '<li class="vuln-item low"><div class="vuln-description">✓ No vulnerabilities detected</div></li>' : ''}
                </ul>
            </div>
        </div>
    `;
    
    return card;
}

// Reset scan button
function resetScanButton() {
    startScanBtn.disabled = false;
    startScanBtn.textContent = '🚀 Start Scan';
}