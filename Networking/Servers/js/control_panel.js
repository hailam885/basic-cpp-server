function addLog(message, type = 'info') {
    const logContainer = document.getElementById('log-container');
    const entry = document.createElement('div');
    entry.className = `log-entry ${type}`;
    const timestamp = new Date().toLocaleTimeString();
    entry.innerHTML = `<span class="timestamp">[${timestamp}]</span> ${message}`;
    logContainer.insertBefore(entry, logContainer.firstChild);
    while (logContainer.children.length > 100) { // Keep only last 100 entries
        logContainer.removeChild(logContainer.lastChild);
    }
}

function formatBytes(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB';
    if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
    if (bytes < 1024 * 1024 * 1024 * 1024) return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
    return (bytes / (1024 * 1024 * 1024 * 1024)).toFixed(2) + ' TB';
}

function formatTime(seconds) {
    const year = Math.floor(seconds / 31536000);
    const days = Math.floor((seconds % 31536000) / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    if (year > 0) return `${year}y ${days}d ${hours}h ${mins}m ${secs}s`;
    if (days > 0) return `${days}d ${hours}h ${mins}m ${secs}s`;
    if (hours > 0) return `${hours}h ${mins}m ${secs}s`;
    if (mins > 0) return `${mins}m ${secs}s`;
    return `${secs}s`;
}

function formatNum(num, separator = ',') {
    return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, separator);
}

function updateSegmentedBar(segments, percentages) {
    segments.forEach((segmentId, index) => {
        const segment = document.getElementById(segmentId);
        if (segment) {
            segment.style.width = percentages[index] + '%';
        }
    });
}

function colorValue(elementId, value, thresholds) {
    const element = document.getElementById(elementId);
    if (element) {
        element.classList.remove('normal', 'warning', 'critical');
        if (value < thresholds.warning) {
            element.classList.add('normal');
        } else if (value < thresholds.critical) {
            element.classList.add('warning');
        } else {
            element.classList.add('critical');
        }
    }
}

function updateProgressBar(elementId, percent, pressureLevel = null) {
    const progressBar = document.getElementById(elementId);
    if (progressBar) {
        progressBar.style.width = Math.min(percent, 100) + '%';
        // If we have memory pressure level, use that instead of percentage
        if (pressureLevel !== null) {
            // macOS memory pressure: 1=normal, 2=warning, 4=critical
            if (pressureLevel === 1) {
                progressBar.style.background = 'linear-gradient(90deg, #10b981, #059669)';
            } else if (pressureLevel === 2) {
                progressBar.style.background = 'linear-gradient(90deg, #f59e0b, #d97706)';
            } else if (pressureLevel === 4) {
                progressBar.style.background = 'linear-gradient(90deg, #ef4444, #dc2626)';
            }
        } else {
            // Fallback: Color coding based on percentage
            if (percent < 50) {
                progressBar.style.background = 'linear-gradient(90deg, #10b981, #059669)';
            } else if (percent < 75) {
                progressBar.style.background = 'linear-gradient(90deg, #f59e0b, #d97706)';
            } else {
                progressBar.style.background = 'linear-gradient(90deg, #ef4444, #dc2626)';
            }
        }
    }
}

async function updateMetrics() {
    try {
        const response = await fetch('/admin/metrics');
        if (!response.ok) throw new Error('Failed to fetch metrics');
        const metrics = await response.json();
        const cpuTotal = metrics.cpu_usage_percent;
        const cpuUser = metrics.cpu_user_percent;
        const cpuSystem = metrics.cpu_system_percent;
        const cpuIdle = metrics.cpu_idle_percent;
        document.getElementById('cpu-usage').textContent = cpuTotal.toFixed(2) + '%';
        document.getElementById('cpu-user').textContent = cpuUser.toFixed(2) + '%';
        document.getElementById('cpu-system').textContent = cpuSystem.toFixed(2) + '%';
        document.getElementById('cpu-idle').textContent = cpuIdle.toFixed(2) + '%';
        const cpuElement = document.getElementById('cpu-usage');
        cpuElement.classList.remove('normal', 'warning', 'critical');
        cpuElement.classList.add('value-colored');
        if (cpuTotal < 50) {
            cpuElement.classList.add('normal');
        } else if (cpuTotal < 80) {
            cpuElement.classList.add('warning');
        } else {
            cpuElement.classList.add('critical');
        }
        updateSegmentedBar(
            ['cpu-user-segment', 'cpu-system-segment', 'cpu-idle-segment'],
            [cpuUser, cpuSystem, cpuIdle]
        );
        const memActive = metrics.memory_active_percent;
        const memWired = metrics.memory_wired_percent;
        const memCompressed = metrics.memory_compressed_percent;
        const memFree = metrics.memory_free_percent;
        document.getElementById('memory-usage').textContent = formatBytes(metrics.memory_used_bytes);
        document.getElementById('mem-active').textContent = memActive.toFixed(2) + '%';
        document.getElementById('mem-wired').textContent = memWired.toFixed(2) + '%';
        document.getElementById('mem-compressed').textContent = memCompressed.toFixed(1) + '%';
        document.getElementById('mem-free').textContent = memFree.toFixed(2) + '%';
        const totalMemGB = metrics.memory_total_bytes / (1024 * 1024 * 1024);
        document.getElementById('total-memory').textContent = totalMemGB.toFixed(2) + ' GB';
        const pressureLevel = metrics.memory_pressure || null;
        const memElement = document.getElementById('memory-usage');
        memElement.classList.remove('normal', 'warning', 'critical');
        memElement.classList.add('value-colored');
        if (pressureLevel === 1) {
            memElement.classList.add('normal');
            document.getElementById('memory-percent').textContent = metrics.memory_percent.toFixed(2) + '% of total (Normal)';
        } else if (pressureLevel === 2) {
            memElement.classList.add('warning');
            document.getElementById('memory-percent').textContent = metrics.memory_percent.toFixed(2) + '% of total (Warning)';
        } else if (pressureLevel === 4) {
            memElement.classList.add('critical');
            document.getElementById('memory-percent').textContent = metrics.memory_percent.toFixed(2) + '% of total (Critical)';
        } else {
            memElement.classList.add('normal');
            document.getElementById('memory-percent').textContent = metrics.memory_percent.toFixed(2) + '% of total';
        }
        updateSegmentedBar(
            ['mem-active-segment', 'mem-wired-segment', 'mem-compressed-segment', 'mem-free-segment'],
            [memActive, memWired, memCompressed, memFree]
        );
        //.memory_pressure || null;
        document.getElementById('memory-percent').textContent = metrics.memory_percent.toFixed(2) + '% of total';
        updateProgressBar('memory-progress', metrics.memory_percent, pressureLevel);
        const memoryCard = document.getElementById('memory-percent');
        if (pressureLevel === 1) {
            memoryCard.textContent = metrics.memory_percent.toFixed(2) + '% of total (Normal)';
        } else if (pressureLevel === 2) {
            memoryCard.textContent = metrics.memory_percent.toFixed(2) + '% of total (Warning)';
        } else if (pressureLevel === 4) {
            memoryCard.textContent = metrics.memory_percent.toFixed(2) + '% of total (Critical)';
        } else {
            memoryCard.textContent = metrics.memory_percent.toFixed(2) + '% of total';
        }
        document.getElementById('total-memory').textContent = totalMemGB.toFixed(2) + ' GB';
        document.getElementById('uptime').textContent = formatTime(metrics.uptime_seconds);
        document.getElementById('total-requests').textContent = formatNum(metrics.total_requests);
        document.getElementById('req-per-sec').textContent = metrics.requests_per_second.toFixed(2);
        document.getElementById('instant-rps').textContent = metrics.instantaneous_rps.toFixed(2);
        document.getElementById('thread-count').textContent = metrics.thread_count;
        const successRate = metrics.total_requests > 0 ? (metrics.successful_requests / metrics.total_requests * 100).toFixed(2) : 100;
        document.getElementById('success-rate').textContent = successRate + '%';
        document.getElementById('bytes-sent').textContent = formatBytes(metrics.bytes_sent);
        document.getElementById('bytes-received').textContent = formatBytes(metrics.bytes_received);
    } catch (error) {
        console.error('Error fetching metrics:', error);
        addLog('Failed to update metrics', 'error');
    }
}

async function reloadCache() {
    if (!confirm('Reload all cached files? This will reload files from disk.')) return;
    addLog('Reloading cache...', 'info');
    try {
        const response = await fetch('/admin/cache/reload', { method: 'POST' });
        if (!response.ok) throw new Error('Failed to reload cache');
        const result = await response.json();
        addLog(`Cache reloaded: ${result.files_loaded} files`, 'success');
    } catch (error) {
        addLog('Failed to reload cache', 'error');
        console.error(error);
    }
}

async function clearCache() {
    if (!confirm('Clear all cached files? This will require a cache reload.')) return;
    addLog('Clearing cache...', 'warning');
    try {
        const response = await fetch('/admin/cache/clear', { method: 'POST' });
        if (!response.ok) throw new Error('Failed to clear cache');
        addLog('Cache cleared successfully', 'success');
    } catch (error) {
        addLog('Failed to clear cache', 'error');
    }
}

async function exportMetrics() {
    try {
        const response = await fetch('/admin/metrics');
        const metrics = await response.json();
        const dataStr = JSON.stringify(metrics, null, 2);
        const dataBlob = new Blob([dataStr], { type: 'application/json' });
        const url = URL.createObjectURL(dataBlob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `server-metrics-${Date.now()}.json`;
        link.click();
        URL.revokeObjectURL(url);
        addLog('Metrics exported successfully', 'success');
    } catch (error) {
        addLog('Failed to export metrics', 'error');
    }
}

async function shutdownServer() {
    const password = prompt('Enter admin password to shutdown server:');
    if (!password) return;
    if (!confirm('Are you ABSOLUTELY SURE you want to shutdown the server? This cannot be undone!')) {
        return;
    }
    addLog('Initiating graceful shutdown...', 'error');
    const statusBadge = document.getElementById('server-status');
    statusBadge.innerHTML = '<span class="status-dot" style="background:#ef4444"></span><span>SHUTTING DOWN</span>';
    statusBadge.style.background = 'rgba(239, 68, 68, 0.1)';
    statusBadge.style.borderColor = 'rgba(239, 68, 68, 0.3)';
    statusBadge.style.color = '#ef4444';
    try {
        const response = await fetch('/admin/shutdown', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ password: password })
        });
        if (!response.ok) {
            throw new Error('Shutdown failed - incorrect password?');
        }
        addLog('Server shutdown initiated', 'error');
        clearInterval(refreshInterval);
        setTimeout(() => {
            statusBadge.innerHTML = '<span class="status-dot" style="background:#64748b"></span><span>OFFLINE</span>';
            addLog('Server is now offline', 'error');
        }, 1000);
    } catch (error) {
        addLog('Shutdown failed: ' + error.message, 'error');
        statusBadge.innerHTML = '<span class="status-dot"></span><span>ONLINE</span>';
        statusBadge.style.background = 'rgba(16, 185, 129, 0.1)';
        statusBadge.style.borderColor = 'rgba(16, 185, 129, 0.3)';
        statusBadge.style.color = '#10b981';
    }
}

let refreshInterval;
updateMetrics();
refreshInterval = setInterval(updateMetrics, 1000);