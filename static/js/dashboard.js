function drawDashboardCharts(riskCounts, timestamps) {
    const gc = '#1e1e1e';
    const tc = '#444';
    const rColors = {
        Low: '#4caf50',
        Medium: '#ff9800',
        High: '#f44336',
        Critical: '#e91e63'
    };

    new Chart(document.getElementById('risk-chart'), {
        type: 'doughnut',
        data: {
            labels: Object.keys(riskCounts),
            datasets: [{
                data: Object.values(riskCounts),
                backgroundColor: Object.keys(riskCounts).map(k => rColors[k] || '#555'),
                borderColor: '#0f0f0f',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: { color: tc, font: { family: 'Inter', size: 11 }, boxWidth: 10 }
                }
            }
        }
    });

    const dc = {};
    timestamps.forEach(ts => {
        const d = ts.slice(0, 10);
        dc[d] = (dc[d] || 0) + 1;
    });

    const days = Object.keys(dc).sort().slice(-14);

    new Chart(document.getElementById('time-chart'), {
        type: 'line',
        data: {
            labels: days,
            datasets: [{
                data: days.map(d => dc[d]),
                borderColor: '#555',
                backgroundColor: 'rgba(255,255,255,0.03)',
                tension: 0.3,
                pointBackgroundColor: '#888',
                pointRadius: 3,
                fill: true
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { ticks: { color: tc, font: { size: 10 } }, grid: { color: gc } },
                y: { ticks: { color: tc, stepSize: 1 }, grid: { color: gc }, beginAtZero: true }
            }
        }
    });
}