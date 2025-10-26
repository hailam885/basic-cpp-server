// Floating particles generation
function createParticles() {
    const container = document.getElementById('particles');
    const particleCount = 30;
    for (let i = 0; i < particleCount; i++) {
        const particle = document.createElement('div');
        particle.className = 'particle';
        particle.style.left = Math.random() * 100 + '%';
        particle.style.animationDelay = Math.random() * 20 + 's';
        particle.style.animationDuration = (15 + Math.random() * 10) + 's';
        container.appendChild(particle);
    }
}

// Scroll fade-in animation
function handleScrollAnimation() {
    const elements = document.querySelectorAll('.scroll-fade');
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('visible');
            }
        });
    }, {
        threshold: 0.1
    });
    elements.forEach(el => observer.observe(el));
}

// Smooth scroll
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({
                behavior: 'smooth',
                block: 'start'
            });
        }
    });
});

// Fetch live stats (optional - connects to your server metrics)
async function updateLiveStats() {
    try {
        const response = await fetch('/admin/metrics');
        if (response.ok) {
            const metrics = await response.json();
            // Update stats with real data
            const uptimeHours = Math.floor(metrics.uptime_seconds / 3600);
            document.getElementById('stat-uptime').textContent = 
                uptimeHours > 24 ? Math.floor(uptimeHours / 24) + 'd' : uptimeHours + 'h';
            document.getElementById('stat-requests').textContent = 
                metrics.total_requests > 1000 ? 
                (metrics.total_requests / 1000).toFixed(1) + 'K+' : 
                metrics.total_requests;
        }
    } catch (error) {
        // Use default values if metrics unavailable
        console.log('Metrics unavailable, using defaults');
    }
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    createParticles();
    handleScrollAnimation();
    updateLiveStats();
    
    // Update stats every 30 seconds
    setInterval(updateLiveStats, 30000);
});