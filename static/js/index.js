const scanMsgs = [
    'Running DNS lookup...',
    'Checking subdomains...',
    'Running Nmap...',
    'Fetching CVEs...',
    'Almost done...'
];

document.getElementById('scan-form').addEventListener('submit', () => {
    document.getElementById('overlay').classList.add('on');
    let i = 0;
    setInterval(() => {
        if (i < scanMsgs.length) {
            document.getElementById('overlay-msg').textContent = scanMsgs[i++];
        }
    }, 5000);
});


function drawCharts(portCount, services) {
    const gc = '#1e1e1e';
    const tc = '#444';

    new Chart(document.getElementById('port-chart'), {
        type: 'bar',
        data: {
            labels: ['Open', 'Other'],
            datasets: [{
                data: [portCount, Math.max(0, 1000 - portCount)],
                backgroundColor: ['rgba(244,67,54,0.6)', 'rgba(255,255,255,0.05)'],
                borderColor: ['#f44336', '#2a2a2a'],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { ticks: { color: tc }, grid: { color: gc } },
                y: { ticks: { color: tc }, grid: { color: gc } }
            }
        }
    });

    const colors = ['#4caf50', '#2196f3', '#ff9800', '#9c27b0', '#00bcd4', '#f44336'];

    new Chart(document.getElementById('svc-chart'), {
        type: 'doughnut',
        data: {
            labels: services.length ? services : ['None'],
            datasets: [{
                data: services.length ? services.map(() => 1) : [1],
                backgroundColor: colors.slice(0, Math.max(services.length, 1)),
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
}