// Navigate to security check
function navigateToHome() {
    window.location.href = "/home";
}

// Smooth scroll to "How It Works" section
function scrollToHowItWorks() {
    const howItWorksSection = document.querySelector('.how-it-works');
    if (howItWorksSection) {
        howItWorksSection.scrollIntoView({ 
            behavior: 'smooth',
            block: 'start'
        });
    }
}

window.addEventListener('DOMContentLoaded', () => {
    fetch('/api/stats')
        .then(res => res.json())
        .then(data => {
            if (data.ml_stats) {
                const accEl = document.getElementById('ai-accuracy-value');
                const sampleEl = document.getElementById('total-samples-value');
                if (accEl) accEl.innerText = data.ml_stats.accuracy + '%';
                if (sampleEl) sampleEl.innerText = data.ml_stats.total_samples;
            }
        })
        .catch(err => console.error("Could not fetch metrics:", err));
});
