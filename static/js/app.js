// SmartIDS Web Interface JavaScript
// Main application logic for real-time intrusion detection visualization

// Global state
let simulationInterval = null;
let liveCaptureInterval = null;
let isSimulating = false;
let isLiveCapturing = false;
let detectionHistory = [];
let stats = {
    total: 0,
    benign: 0,
    attacks: 0,
    truePositives: 0,
    falsePositives: 0,
    falseNegatives: 0,
    trueNegatives: 0
};

// Chart instances
let pieChart = null;
let lineChart = null;

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    console.log('SmartIDS initializing...');
    initializeCharts();
    setupEventListeners();
    loadInitialStats();
});

// Initialize Chart.js charts
function initializeCharts() {
    // Pie Chart - Traffic Distribution
    const pieCtx = document.getElementById('pieChart').getContext('2d');
    pieChart = new Chart(pieCtx, {
        type: 'pie',
        data: {
            labels: ['Benign Traffic', 'Attack Traffic'],
            datasets: [{
                data: [0, 0],
                backgroundColor: [
                    'rgba(40, 167, 69, 0.8)',
                    'rgba(220, 53, 69, 0.8)'
                ],
                borderColor: [
                    'rgba(40, 167, 69, 1)',
                    'rgba(220, 53, 69, 1)'
                ],
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'bottom'
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = context.parsed || 0;
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = total > 0 ? ((value / total) * 100).toFixed(1) : 0;
                            return `${label}: ${value} (${percentage}%)`;
                        }
                    }
                }
            }
        }
    });

    // Line Chart - Real-Time Detection
    const lineCtx = document.getElementById('lineChart').getContext('2d');
    lineChart = new Chart(lineCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'Benign',
                    data: [],
                    borderColor: 'rgba(40, 167, 69, 1)',
                    backgroundColor: 'rgba(40, 167, 69, 0.2)',
                    tension: 0.4,
                    fill: true
                },
                {
                    label: 'Attack',
                    data: [],
                    borderColor: 'rgba(220, 53, 69, 1)',
                    backgroundColor: 'rgba(220, 53, 69, 0.2)',
                    tension: 0.4,
                    fill: true
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        stepSize: 1
                    }
                }
            },
            plugins: {
                legend: {
                    position: 'top'
                }
            }
        }
    });
}

// Setup event listeners
function setupEventListeners() {
    // Packet rate slider
    const packetRate = document.getElementById('packetRate');
    const rateValue = document.getElementById('rateValue');
    packetRate.addEventListener('input', function() {
        rateValue.textContent = `${this.value} pkt/sec`;
    });

    // Model selection dropdown - prevent selecting disabled options
    const modelSelect = document.getElementById('modelSelect');
    modelSelect.addEventListener('change', function() {
        const selectedOption = this.options[this.selectedIndex];
        if (selectedOption.disabled) {
            // If disabled option selected, revert to auto
            this.value = 'auto';
            showAlert('Selected model is not available. Using Auto mode.', 'warning');
        }
    });

    // Start simulation button
    document.getElementById('startSimulation').addEventListener('click', startSimulation);

    // Stop simulation button
    document.getElementById('stopSimulation').addEventListener('click', stopSimulation);

    // Live capture buttons
    document.getElementById('startLiveCapture').addEventListener('click', startLiveCapture);
    document.getElementById('stopLiveCapture').addEventListener('click', stopLiveCapture);

    // Reset stats button
    document.getElementById('resetStats').addEventListener('click', resetStats);

    // Initial alert structure setup (removed modelInfo listener since button was commented out)
}

// Start the simulation
function startSimulation() {
    if (isSimulating) return;

    const modelSelect = document.getElementById('modelSelect');
    const selectedOption = modelSelect.options[modelSelect.selectedIndex];
    
    // Check if selected option is disabled
    if (selectedOption.disabled) {
        showAlert('Selected model is not available. Please select a different model.', 'danger');
        return;
    }

    const model = modelSelect.value;
    const rate = parseInt(document.getElementById('packetRate').value);
    const interval = 1000 / rate; // Convert to milliseconds

    console.log(`Starting simulation with ${model} at ${rate} pkt/sec`);

    isSimulating = true;
    document.getElementById('startSimulation').disabled = true;
    document.getElementById('stopSimulation').disabled = false;
    document.getElementById('startLiveCapture').disabled = true; // Disable live capture while simulating

    // Start periodic simulation - read model from dropdown each time to allow dynamic switching
    simulationInterval = setInterval(() => {
        simulatePacket(); // Will read current model from dropdown
    }, interval);

    showAlert('Simulation started', 'success');
}

// Stop the simulation
function stopSimulation() {
    if (!isSimulating) return;

    console.log('Stopping simulation');

    isSimulating = false;
    clearInterval(simulationInterval);
    simulationInterval = null;

    document.getElementById('startSimulation').disabled = false;
    document.getElementById('stopSimulation').disabled = true;
    document.getElementById('startLiveCapture').disabled = false; // Re-enable live capture

    showAlert('Simulation stopped', 'info');
}

// Simulate a single packet
async function simulatePacket(model) {
    try {
        // Always read current model from dropdown (allows switching during simulation)
        const modelSelect = document.getElementById('modelSelect');
        const selectedOption = modelSelect.options[modelSelect.selectedIndex];
        
        // Use provided model if given, otherwise read from dropdown
        if (!model) {
            if (selectedOption.disabled) {
                model = 'auto'; // Fall back to auto if selected model is disabled
            } else {
                model = modelSelect.value;
            }
        }
        
        console.log(`Simulating with model: ${model}`);
        
        const response = await fetch('/api/simulate', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                model: model,
                num_packets: 1
            })
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();

        if (data.error) {
            console.error('Simulation error:', data.error);
            showAlert(data.error, 'danger');
            stopSimulation();
            return;
        }

        // Process results
        if (data.results && data.results.length > 0) {
            data.results.forEach(result => {
                processDetection(result);
            });
        }

        // Update stats
        if (data.stats) {
            updateStats(data.stats);
        }

    } catch (error) {
        console.error('Simulation error:', error);
        showAlert(`Error: ${error.message}`, 'danger');
        stopSimulation();
    }
}

// Start Live Capture
async function startLiveCapture() {
    if (isLiveCapturing) return;

    const iface = document.getElementById('networkInterface').value;
    
    document.getElementById('startLiveCapture').disabled = true;
    document.getElementById('stopLiveCapture').disabled = false;
    document.getElementById('startSimulation').disabled = true; // Disable simulation while live
    document.getElementById('captureStatsContainer').style.display = 'block';
    
    try {
        const response = await fetch('/api/live/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ interface: iface })
        });

        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        
        const data = await response.json();
        if (data.error) throw new Error(data.error);
        
        isLiveCapturing = true;
        console.log(`Live capture started on ${data.interface || 'auto-detect'}`);
        showAlert(`Live capture started on interface: ${data.interface || 'auto-detect'}`, 'success');
        
        // Poll for results every second
        liveCaptureInterval = setInterval(pollLiveResults, 1000);
        
    } catch (error) {
        console.error('Failed to start live capture:', error);
        showAlert(`Failed to start live capture: ${error.message}`, 'danger');
        stopLiveCapture();
    }
}

// Stop Live Capture
async function stopLiveCapture() {
    if (!isLiveCapturing && !document.getElementById('stopLiveCapture').disabled) {
        // Force UI reset even if stat out of sync
    } else if (!isLiveCapturing) {
        return;
    }

    try {
        await fetch('/api/live/stop', { method: 'POST' });
    } catch (e) {
        console.error('Error stopping capture:', e);
    }
    
    isLiveCapturing = false;
    if (liveCaptureInterval) {
        clearInterval(liveCaptureInterval);
        liveCaptureInterval = null;
    }
    
    document.getElementById('startLiveCapture').disabled = false;
    document.getElementById('stopLiveCapture').disabled = true;
    document.getElementById('startSimulation').disabled = false;
    document.getElementById('captureStatsContainer').style.display = 'none';
    
    showAlert('Live capture stopped', 'info');
}

// Poll for live results
async function pollLiveResults() {
    if (!isLiveCapturing) return;
    
    try {
        const modelSelect = document.getElementById('modelSelect');
        const model = modelSelect.disabled ? 'auto' : modelSelect.value;
        
        const response = await fetch(`/api/live/results?model=${model}`);
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        
        const data = await response.json();
        
        if (data.error) throw new Error(data.error);
        
        // Process results
        if (data.results && data.results.length > 0) {
            data.results.forEach(result => {
                // Ensure correct structure for processDetection
                // live results use flow_key as packet_id, we map it back
                processDetection(result);
            });
        }
        
        // Update capture stats if available
        if (data.capture_stats) {
            document.getElementById('packetsProcessed').textContent = data.capture_stats.packets_processed || 0;
            document.getElementById('activeFlows').textContent = data.capture_stats.active_flows || 0;
        }
        
        // The processDetection function handles global stats incrementing locally for the charts,
        // so we don't need to aggressively sync data.stats here unless we drift heavily.
        
    } catch (error) {
        console.error('Error polling live results:', error);
    }
}

// Process a detection result
function processDetection(result) {
    // Add to history
    detectionHistory.unshift(result);
    if (detectionHistory.length > 100) {
        detectionHistory.pop();
    }

    // Update local stats
    stats.total++;
    if (result.prediction === 0) {
        stats.benign++;
    } else {
        stats.attacks++;
    }

    // Update confusion matrix stats if actual label is available
    if (result.hasOwnProperty('actual')) {
        if (result.actual === 1 && result.prediction === 1) {
            stats.truePositives++;
        } else if (result.actual === 0 && result.prediction === 1) {
            stats.falsePositives++;
        } else if (result.actual === 1 && result.prediction === 0) {
            stats.falseNegatives++;
        } else if (result.actual === 0 && result.prediction === 0) {
            stats.trueNegatives++;
        }
    }

    // Update UI
    updateDetectionTable(result);
    updateCharts();
    updateStatistics();

    // Show alert for attacks
    if (result.prediction === 1) {
        const confidence = (result.confidence * 100).toFixed(1);
        showAlert(
            `Attack detected! Confidence: ${confidence}%`,
            'danger',
            2000
        );
    }
}

// Update the detection table
function updateDetectionTable(result) {
    const table = document.getElementById('detectionTable');
    
    // Remove placeholder row if it exists
    const placeholder = table.querySelector('tr td[colspan="6"]');
    if (placeholder) {
        placeholder.parentElement.remove();
    }

    // Create new row
    const row = document.createElement('tr');
    
    // Determine colors and icons
    const predClass = result.prediction === 0 ? 'text-success' : 'text-danger';
    const predIcon = result.prediction === 0 ? 'fa-check-circle' : 'fa-exclamation-triangle';
    const predLabel = result.label || (result.prediction === 0 ? 'BENIGN' : 'ATTACK');
    
    let actualHTML = '-';
    
    if (result.hasOwnProperty('actual')) {
        const actualClass = result.actual === 0 ? 'text-success' : 'text-danger';
        const actualLabel = result.actual_label || (result.actual === 0 ? 'BENIGN' : 'ATTACK');
        actualHTML = `<span class="${actualClass}">${actualLabel}</span>`;
    }

    const timestamp = new Date(result.timestamp).toLocaleTimeString();
    const confidence = (result.confidence * 100).toFixed(1);
    const model = result.model || result.model_selected || '-';

    row.innerHTML = `
        <td>${timestamp}</td>
        <td><code>${result.packet_id}</code></td>
        <td><span class="badge bg-secondary">${model}</span></td>
        <td><span class="${predClass}"><i class="fas ${predIcon}"></i> ${predLabel}</span></td>
        <td><span class="badge bg-info">${confidence}%</span></td>
        <td>${actualHTML}</td>
    `;

    // Highlight if attack
    if (result.prediction === 1) {
        row.classList.add('table-danger');
    }

    // Add to table
    table.insertBefore(row, table.firstChild);

    // Keep only last 50 rows
    while (table.children.length > 50) {
        table.removeChild(table.lastChild);
    }

    // Update detection count
    document.getElementById('detectionCount').textContent = detectionHistory.length;
}

// Update charts
function updateCharts() {
    // Update pie chart
    pieChart.data.datasets[0].data = [stats.benign, stats.attacks];
    pieChart.update('none'); // Use 'none' mode for performance

    // Update line chart (keep last 20 data points)
    const now = new Date().toLocaleTimeString();
    
    if (lineChart.data.labels.length >= 20) {
        lineChart.data.labels.shift();
        lineChart.data.datasets[0].data.shift();
        lineChart.data.datasets[1].data.shift();
    }

    lineChart.data.labels.push(now);
    lineChart.data.datasets[0].data.push(stats.benign);
    lineChart.data.datasets[1].data.push(stats.attacks);
    lineChart.update('none');
}

// Update statistics display
function updateStatistics() {
    document.getElementById('totalPackets').textContent = stats.total;
    document.getElementById('benignCount').textContent = stats.benign;
    document.getElementById('attackCount').textContent = stats.attacks;

    // Calculate attack rate
    const attackRate = stats.total > 0 ? ((stats.attacks / stats.total) * 100).toFixed(1) : 0;
    document.getElementById('attackRate').textContent = `${attackRate}%`;

    // Calculate accuracy if we have actual labels
    const totalWithLabels = stats.truePositives + stats.falsePositives + 
                           stats.falseNegatives + stats.trueNegatives;
    if (totalWithLabels > 0) {
        const accuracy = ((stats.truePositives + stats.trueNegatives) / totalWithLabels * 100).toFixed(1);
        document.getElementById('accuracy').textContent = `${accuracy}%`;
    } else {
        document.getElementById('accuracy').textContent = '-';
    }

    // Update confusion matrix stats
    document.getElementById('truePositives').textContent = stats.truePositives;
    document.getElementById('falsePositives').textContent = stats.falsePositives;
    document.getElementById('falseNegatives').textContent = stats.falseNegatives;
}

// Update stats from server
function updateStats(serverStats) {
    // We use local stats for better real-time updates
    // But we can sync with server if needed
}

// Load initial statistics
async function loadInitialStats() {
    try {
        const response = await fetch('/api/stats');
        const data = await response.json();
        updateStats(data);
    } catch (error) {
        console.error('Error loading stats:', error);
    }
}

// Reset statistics
async function resetStats() {
    if (!confirm('Are you sure you want to reset all statistics?')) {
        return;
    }

    try {
        const response = await fetch('/api/reset_stats', {
            method: 'POST'
        });

        if (response.ok) {
            // Reset local stats
            stats = {
                total: 0,
                benign: 0,
                attacks: 0,
                truePositives: 0,
                falsePositives: 0,
                falseNegatives: 0,
                trueNegatives: 0
            };
            detectionHistory = [];

            // Clear table
            const table = document.getElementById('detectionTable');
            table.innerHTML = `
                <tr>
                    <td colspan="6" class="text-center text-muted">
                        <i class="fas fa-info-circle"></i> Start simulation to see detections
                    </td>
                </tr>
            `;

            // Reset charts
            pieChart.data.datasets[0].data = [0, 0];
            pieChart.update();

            lineChart.data.labels = [];
            lineChart.data.datasets[0].data = [];
            lineChart.data.datasets[1].data = [];
            lineChart.update();

            // Update statistics display
            updateStatistics();

            showAlert('Statistics reset successfully', 'success');
        } else {
            throw new Error('Failed to reset statistics');
        }
    } catch (error) {
        console.error('Error resetting stats:', error);
        showAlert(`Error: ${error.message}`, 'danger');
    }
}

// Show model information
async function showModelInfo() {
    const modelName = document.getElementById('modelSelect').value;
    const modal = new bootstrap.Modal(document.getElementById('modelInfoModal'));
    const content = document.getElementById('modelInfoContent');

    // Special case: Auto mode is a meta-model
    if (modelName === 'auto') {
        // Build list of available concrete models from the select options
        const select = document.getElementById('modelSelect');
        const available = [];
        Array.from(select.options).forEach(opt => {
            if (opt.value !== 'auto' && !opt.disabled) {
                available.push(opt.text.replace(/\s*\(.*\)$/, ''));
            }
        });

        let html = `
            <h6><i class="fas fa-robot"></i> Auto Mode</h6>
            <p>Auto mode evaluates every available model for each packet and selects the prediction with the <strong>highest confidence</strong>.</p>
        `;

        if (available.length > 0) {
            html += `
                <p><strong>Currently used models:</strong> ${available.join(', ')}</p>
            `;
        } else {
            html += `
                <p class="text-danger"><strong>No concrete models are currently available.</strong></p>
            `;
        }

        html += `
            <p class="mb-0 text-muted">
                This is useful when you are not sure which classifier performs best in the current traffic mix.
                You can still force a specific model from the selector if you want to inspect its behaviour.
            </p>
        `;

        content.innerHTML = html;
        modal.show();
        return;
    }

    // Show loading for concrete model info
    content.innerHTML = `
        <div class="text-center">
            <div class="spinner-border" role="status">
                <span class="visually-hidden">Loading...</span>
            </div>
        </div>
    `;

    modal.show();

    try {
        const response = await fetch(`/api/model_info/${modelName}`);
        
        if (!response.ok) {
            throw new Error('Model information not available');
        }

        const data = await response.json();

        let html = `
            <div class="row">
                <div class="col-md-6">
                    <h6><i class="fas fa-tag"></i> Model Details</h6>
                    <table class="table table-sm">
                        <tr><td><strong>Name:</strong></td><td>${data.name}</td></tr>
                        <tr><td><strong>Type:</strong></td><td>${data.type}</td></tr>
                        <tr><td><strong>Status:</strong></td><td><span class="badge bg-success">Available</span></td></tr>
        `;

        if (data.n_estimators) {
            html += `<tr><td><strong>Estimators:</strong></td><td>${data.n_estimators}</td></tr>`;
        }
        if (data.max_depth !== undefined && data.max_depth !== null) {
            html += `<tr><td><strong>Max Depth:</strong></td><td>${data.max_depth}</td></tr>`;
        }
        if (typeof data.feature_count === 'number') {
            html += `<tr><td><strong>Input Features:</strong></td><td>${data.feature_count}</td></tr>`;
        }
        if (typeof data.has_scaler === 'boolean') {
            const badge = data.has_scaler
                ? '<span class="badge bg-success">Yes</span>'
                : '<span class="badge bg-secondary">No</span>';
            html += `<tr><td><strong>Uses Scaler:</strong></td><td>${badge}</td></tr>`;
        }
        if (typeof data.supports_proba === 'boolean') {
            const badge = data.supports_proba
                ? '<span class="badge bg-success">Yes</span>'
                : '<span class="badge bg-secondary">No</span>';
            html += `<tr><td><strong>Probability Output:</strong></td><td>${badge}</td></tr>`;
        }

        html += `
                    </table>
                </div>
        `;

        if (data.top_features) {
            html += `
                <div class="col-md-6">
                    <h6><i class="fas fa-star"></i> Top 10 Features</h6>
                    <div class="list-group list-group-flush" style="max-height: 300px; overflow-y: auto;">
            `;
            
            data.top_features.forEach((feat, idx) => {
                const percentage = (feat.importance * 100).toFixed(2);
                html += `
                    <div class="list-group-item d-flex justify-content-between align-items-center">
                        <small>${idx + 1}. ${feat.name}</small>
                        <span class="badge bg-primary rounded-pill">${percentage}%</span>
                    </div>
                `;
            });

            html += `
                    </div>
                </div>
            `;
        }

        html += '</div>';

        content.innerHTML = html;

    } catch (error) {
        console.error('Error loading model info:', error);
        content.innerHTML = `
            <div class="alert alert-danger">
                <i class="fas fa-exclamation-triangle"></i> ${error.message}
            </div>
        `;
    }
}

// Show alert message
function showAlert(message, type = 'info', duration = 3000) {
    const alertArea = document.getElementById('alertArea');
    
    const alert = document.createElement('div');
    alert.className = `alert alert-${type} alert-dismissible fade show`;
    alert.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;

    alertArea.appendChild(alert);

    // Auto-dismiss after duration
    if (duration > 0) {
        setTimeout(() => {
            alert.classList.remove('show');
            setTimeout(() => alert.remove(), 150);
        }, duration);
    }
}

console.log('SmartIDS JavaScript loaded successfully');