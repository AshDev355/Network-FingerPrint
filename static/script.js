// Store chart instances for destruction
let charts = {
    protocol: null,
    size: null,
    timeline: null
};

// URL validation
function validateUrl(url) {
    const pattern = /^https?:\/\/.+\..+/i;
    return pattern.test(url);
}

// Single URL Analysis
async function analyzeUrl() {
    const urlInput = document.getElementById('urlInput');
    const url = urlInput.value.trim();
    const errorDiv = document.getElementById('urlError');
    const loadingDiv = document.getElementById('loadingIndicator');
    const resultsDiv = document.getElementById('resultsSection');
    const analyzeBtn = document.getElementById('analyzeBtn');
    
    // Clear previous state
    errorDiv.textContent = '';
    resultsDiv.style.display = 'none';
    
    // Validate URL
    if (!url) {
        errorDiv.textContent = 'Please enter a URL';
        return;
    }
    
    if (!validateUrl(url)) {
        errorDiv.textContent = 'Invalid URL format. Must start with http:// or https:// and have a valid domain';
        return;
    }
    
    // Show loading state
    loadingDiv.style.display = 'block';
    analyzeBtn.disabled = true;
    analyzeBtn.textContent = 'Capturing...';
    
    try {
        const response = await fetch('/api/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url: url })
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'Failed to analyze URL');
        }
        
        if (data.status === 'success') {
            displayResults(data.fingerprint);
            drawCharts(data.fingerprint);
            resultsDiv.style.display = 'block';
        } else {
            throw new Error(data.error || 'Analysis failed');
        }
    } catch (error) {
        errorDiv.textContent = `Error: ${error.message}`;
    } finally {
        // Reset loading state
        loadingDiv.style.display = 'none';
        analyzeBtn.disabled = false;
        analyzeBtn.textContent = '🔍 Analyze';
    }
}

// Display fingerprint card
function displayResults(fingerprint) {
    const card = document.getElementById('fingerprintCard');
    
    const behaviorClass = `behavior-${fingerprint.behavior_label.split('-')[0]}`;
    
    card.innerHTML = `
        <div class="fingerprint-grid">
            <div class="fingerprint-item">
                <strong>Site URL</strong>
                <span>${fingerprint.site_url}</span>
            </div>
            <div class="fingerprint-item">
                <strong>Capture Time</strong>
                <span>${new Date(fingerprint.capture_timestamp).toLocaleString()}</span>
            </div>
            <div class="fingerprint-item">
                <strong>Total Packets</strong>
                <span>${fingerprint.total_packets.toLocaleString()}</span>
            </div>
            <div class="fingerprint-item">
                <strong>Total Bytes</strong>
                <span>${(fingerprint.total_bytes / 1024).toFixed(2)} KB</span>
            </div>
            <div class="fingerprint-item">
                <strong>Mean Packet Size</strong>
                <span>${fingerprint.mean_packet_size} bytes</span>
            </div>
            <div class="fingerprint-item">
                <strong>Max Packet Size</strong>
                <span>${fingerprint.max_packet_size} bytes</span>
            </div>
            <div class="fingerprint-item">
                <strong>Top Protocol</strong>
                <span>${fingerprint.top_protocol}</span>
            </div>
            <div class="fingerprint-item">
                <strong>Unique IPs</strong>
                <span>${fingerprint.unique_ips.length}</span>
            </div>
            <div class="fingerprint-item">
                <strong>DNS Queries</strong>
                <span>${fingerprint.dns_queries.length}</span>
            </div>
            <div class="fingerprint-item">
                <strong>Behavior</strong>
                <span>${fingerprint.behavior_label} 
                    <span class="behavior-label ${behaviorClass}">
                        ${fingerprint.behavior_label}
                    </span>
                </span>
            </div>
            <div class="fingerprint-item">
                <strong>Confidence</strong>
                <span>${(fingerprint.confidence * 100).toFixed(1)}%</span>
            </div>
        </div>
    `;
}

// Draw charts
function drawCharts(data) {
    // Destroy existing charts
    Object.values(charts).forEach(chart => {
        if (chart) chart.destroy();
    });
    
    drawProtocolChart(data.protocol_distribution);
    drawSizeChart(data.sizes);
    drawTimelineChart(data.timeline);
    
    // Scroll to results
    document.getElementById('resultsSection').scrollIntoView({ behavior: 'smooth' });
}

function drawProtocolChart(protocols) {
    const ctx = document.getElementById('protocolChart').getContext('2d');
    
    const colors = {
        'TCP': '#4CAF50',
        'UDP': '#2196F3', 
        'DNS': '#FF9800',
        'ICMP': '#f44336',
        'HTTPS': '#9C27B0',
        'OTHER': '#607D8B'
    };
    
    charts.protocol = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: Object.keys(protocols),
            datasets: [{
                data: Object.values(protocols),
                backgroundColor: Object.keys(protocols).map(p => colors[p] || '#999'),
                borderWidth: 2,
                borderColor: 'white'
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'bottom'
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            return `${context.label}: ${context.parsed.toFixed(1)}%`;
                        }
                    }
                }
            }
        }
    });
}

function drawSizeChart(sizes) {
    const ctx = document.getElementById('sizeChart').getContext('2d');
    
    // Create histogram buckets
    const buckets = [0, 0, 0, 0, 0, 0];
    const bucketLabels = ['0-100', '101-300', '301-600', '601-1000', '1001-1500', '1500+'];
    
    sizes.forEach(size => {
        if (size <= 100) buckets[0]++;
        else if (size <= 300) buckets[1]++;
        else if (size <= 600) buckets[2]++;
        else if (size <= 1000) buckets[3]++;
        else if (size <= 1500) buckets[4]++;
        else buckets[5]++;
    });
    
    charts.size = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: bucketLabels,
            datasets: [{
                label: 'Packet Count',
                data: buckets,
                backgroundColor: '#667eea',
                borderRadius: 5
            }]
        },
        options: {
            responsive: true,
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        stepSize: 1
                    }
                }
            }
        }
    });
}

function drawTimelineChart(timeline) {
    const ctx = document.getElementById('timelineChart').getContext('2d');
    
    const labels = Object.keys(timeline).sort((a, b) => a - b);
    const data = labels.map(key => timeline[key]);
    
    charts.timeline = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels.map(l => `${l}s`),
            datasets: [{
                label: 'Bytes per Second',
                data: data,
                borderColor: '#764ba2',
                backgroundColor: 'rgba(118, 75, 162, 0.1)',
                fill: true,
                tension: 0.4,
                pointRadius: 4,
                pointBackgroundColor: '#764ba2'
            }]
        },
        options: {
            responsive: true,
            scales: {
                y: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Bytes'
                    }
                },
                x: {
                    title: {
                        display: true,
                        text: 'Time'
                    }
                }
            }
        }
    });
}

// Compare URLs
async function compareUrls() {
    const url1 = document.getElementById('url1').value.trim();
    const url2 = document.getElementById('url2').value.trim();
    const errorDiv = document.getElementById('compareError');
    const loadingDiv = document.getElementById('compareLoading');
    const resultsSection = document.getElementById('comparisonSection');
    const compareBtn = document.getElementById('compareBtn');
    
    // Clear previous state
    errorDiv.textContent = '';
    resultsSection.style.display = 'none';
    
    // Validate URLs
    if (!url1 || !url2) {
        errorDiv.textContent = 'Please enter both URLs';
        return;
    }
    
    if (!validateUrl(url1) || !validateUrl(url2)) {
        errorDiv.textContent = 'Both URLs must be valid (start with http:// or https://)';
        return;
    }
    
    // Show loading state
    loadingDiv.style.display = 'block';
    compareBtn.disabled = true;
    compareBtn.textContent = 'Comparing...';
    
    try {
        const response = await fetch('/api/compare', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ urls: [url1, url2] })
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'Comparison failed');
        }
        
        if (data.status === 'success') {
            displayComparison(data);
            resultsSection.style.display = 'block';
        } else {
            throw new Error(data.error || 'Comparison failed');
        }
    } catch (error) {
        errorDiv.textContent = `Error: ${