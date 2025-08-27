// Theme toggle functionality
const themeToggleBtn = document.getElementById('theme-toggle-btn');
const themeIcon = document.getElementById('theme-icon');
const htmlElement = document.documentElement;

function setTheme(theme) {
    htmlElement.setAttribute('data-theme', theme);
    localStorage.setItem('theme', theme);
    if (theme === 'dark') {
        themeIcon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12.79A9 9 0 1111.21 3a7 7 0 009.79 9.79z"/>';
    } else {
        themeIcon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"/>';
    }
}

// Load saved theme from localStorage
const savedTheme = localStorage.getItem('theme') || 'light';
setTheme(savedTheme);

themeToggleBtn.addEventListener('click', () => {
    const currentTheme = htmlElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
    setTheme(currentTheme);
});

// XLSX Processing Code
var gk_isXlsx = false;
var gk_xlsxFileLookup = {};
var gk_fileData = {};
function filledCell(cell) {
    return cell !== '' && cell != null;
}
function loadFileData(filename) {
    if (gk_isXlsx && gk_xlsxFileLookup[filename]) {
        try {
            var workbook = XLSX.read(gk_fileData[filename], { type: 'base64' });
            var firstSheetName = workbook.SheetNames[0];
            var worksheet = workbook.Sheets[firstSheetName];
            var jsonData = XLSX.utils.sheet_to_json(worksheet, { header: 1, blankrows: false, defval: '' });
            var filteredData = jsonData.filter(row => row.some(filledCell));
            var headerRowIndex = filteredData.findIndex((row, index) =>
                row.filter(filledCell).length >= filteredData[index + 1]?.filter(filledCell).length
            );
            if (headerRowIndex === -1 || headerRowIndex > 25) {
                headerRowIndex = 0;
            }
            var csv = XLSX.utils.aoa_to_sheet(filteredData.slice(headerRowIndex));
            csv = XLSX.utils.sheet_to_csv(csv, { header: 1 });
            return csv;
        } catch (e) {
            console.error(e);
            return "";
        }
    }
    return gk_fileData[filename] || "";
}

// Simulated data for dashboard
const dashboardData = {
    totalFiles: 125,
    maliciousVsClean: { malicious: 65, clean: 60 },
    malwareTypes: { Trojan: 40, Ransomware: 15, Worm: 10 },
    attackTrends: {
        labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'],
        data: [5, 10, 15, 20, 25, 30]
    }
};

// User state management
let isLoggedIn = localStorage.getItem('isLoggedIn') === 'true';

// Page navigation
const pages = {
    home: document.getElementById('home-page'),
    features: document.getElementById('features-page'),
    malware: document.getElementById('malware-page'),
    report: document.getElementById('report-page'),
    urlAnalysis: document.getElementById('url-analysis-page'),
    ipAnalysis: document.getElementById('ip-analysis-page'),
    portScan: document.getElementById('port-scan-page'),
    mitigation: document.getElementById('mitigation-page'),
    hashAnalysis: document.getElementById('hash-analysis-page'),
    passwordChecker: document.getElementById('password-checker-page'),
    contact: document.getElementById('contact-page')
};

const navBar = document.getElementById('nav-bar');
const buttons = {
    home: document.getElementById('home-btn'),
    features: document.getElementById('features-btn'),
    logout: document.getElementById('logout-btn'),
    malware: document.getElementById('malware-btn'),
    urlAnalysis: document.getElementById('url-analysis-btn'),
    ipAnalysis: document.getElementById('ip-analysis-btn'),
    portScan: document.getElementById('port-scan-btn'),
    hashAnalysis: document.getElementById('hash-analysis-btn'),
    passwordChecker: document.getElementById('password-checker-btn'),
    contact: document.getElementById('contact-btn')
};

const loginBtn = document.getElementById('login-btn');
const signupBtn = document.getElementById('signup-btn');
const dropdownToggle = document.getElementById('dropdown-toggle');
const dropdownMenu = document.getElementById('dropdown-menu');
const analysisDropdown = document.getElementById('analysis-dropdown');

function navColor(page) {
    navBar.className = 'bg-blue-800 text-white p-4 sticky top-0 z-10 shadow-lg transition-colors duration-300';
    if (page === 'malware') navBar.classList.add('bg-blue-500');
    else if (page === 'urlAnalysis') navBar.classList.add('bg-teal-500');
    else if (page === 'ipAnalysis') navBar.classList.add('bg-indigo-500');
    else if (page === 'portScan') navBar.classList.add('bg-purple-500');
    else if (page === 'hashAnalysis') navBar.classList.add('bg-cyan-500');
    else if (page === 'passwordChecker') navBar.classList.add('bg-amber-500');
    else if (page === 'contact') navBar.classList.add('bg-green-500');
}

function showPage(page) {
    // Validate page exists in pages object
    if (!pages[page]) {
        page = 'home'; // Fallback to home if page is invalid
    }
    Object.values(pages).forEach(p => p && p.classList.add('hidden'));
    pages[page]?.classList.remove('hidden');
    navColor(page);
    if (page === 'malware') initDashboardCharts();
    dropdownMenu.classList.add('hidden'); // Close dropdown when navigating
    // Save current page to localStorage
    localStorage.setItem('currentPage', page);
}

function updateNavBar() {
    if (isLoggedIn) {
        loginBtn.classList.add('hidden');
        signupBtn.classList.add('hidden');
        buttons.logout.classList.remove('hidden');
        analysisDropdown.classList.remove('hidden');
    } else {
        loginBtn.classList.remove('hidden');
        signupBtn.classList.remove('hidden');
        buttons.logout.classList.add('hidden');
        analysisDropdown.classList.add('hidden');
    }
}

// Dropdown toggle functionality
dropdownToggle.addEventListener('click', () => {
    dropdownMenu.classList.toggle('hidden');
});

// Close dropdown when clicking outside
document.addEventListener('click', (event) => {
    if (!analysisDropdown.contains(event.target)) {
        dropdownMenu.classList.add('hidden');
    }
});

buttons.home.addEventListener('click', () => showPage('home'));
buttons.features.addEventListener('click', () => showPage('features'));
buttons.malware.addEventListener('click', () => {
    if (isLoggedIn) {
        showPage('malware');
    } else {
        window.location.href = 'login.html';
    }
});
buttons.urlAnalysis.addEventListener('click', () => {
    if (isLoggedIn) {
        showPage('urlAnalysis');
    } else {
        window.location.href = 'login.html';
    }
});
buttons.ipAnalysis.addEventListener('click', () => {
    if (isLoggedIn) {
        showPage('ipAnalysis');
    } else {
        window.location.href = 'login.html';
    }
});
buttons.portScan.addEventListener('click', () => {
    if (isLoggedIn) {
        showPage('portScan');
    } else {
        window.location.href = 'login.html';
    }
});
buttons.hashAnalysis.addEventListener('click', () => {
    if (isLoggedIn) {
        showPage('hashAnalysis');
    } else {
        window.location.href = 'login.html';
    }
});
buttons.passwordChecker.addEventListener('click', () => {
    if (isLoggedIn) {
        showPage('passwordChecker');
    } else {
        window.location.href = 'login.html';
    }
});
buttons.contact.addEventListener('click', () => showPage('contact'));

buttons.logout.addEventListener('click', () => {
    localStorage.setItem('isLoggedIn', 'false');
    isLoggedIn = false;
    updateNavBar();
    showPage('home');
    alert('Logged out successfully.');
});

const mitigationBtn = document.getElementById('mitigation-btn');
mitigationBtn.addEventListener('click', () => showPage('mitigation'));

function initDashboardCharts() {
    document.getElementById('total-files').textContent = dashboardData.totalFiles;

    const ctxMaliciousClean = document.getElementById('malicious-clean-chart').getContext('2d');
    new Chart(ctxMaliciousClean, {
        type: 'pie',
        data: {
            labels: ['Malicious', 'Clean'],
            datasets: [{
                data: [dashboardData.maliciousVsClean.malicious, dashboardData.maliciousVsClean.clean],
                backgroundColor: ['#ff4d4f', '#36b9cc']
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { position: 'top' },
                title: { display: true, text: 'Malicious vs Clean Files' }
            }
        }
    });

    const ctxMalwareTypes = document.getElementById('malware-types-chart').getContext('2d');
    new Chart(ctxMalwareTypes, {
        type: 'bar',
        data: {
            labels: Object.keys(dashboardData.malwareTypes),
            datasets: [{
                label: 'Count',
                data: Object.values(dashboardData.malwareTypes),
                backgroundColor: '#ff4d4f'
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { display: false },
                title: { display: true, text: 'Most Common Malware Types' }
            },
            scales: { y: { beginAtZero: true } }
        }
    });

    const ctxAttackTrend = document.getElementById('attack-trend-chart').getContext('2d');
    new Chart(ctxAttackTrend, {
        type: 'line',
        data: {
            labels: dashboardData.attackTrends.labels,
            datasets: [{
                label: 'Attacks',
                data: dashboardData.attackTrends.data,
                borderColor: '#36b9cc',
                fill: false
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { position: 'top' },
                title: { display: true, text: 'Attack Trends Over Time' }
            },
            scales: { y: { beginAtZero: true } }
        }
    });
}

const analyzeBtn = document.getElementById('analyze-btn');
const fileInput = document.getElementById('file-input');
const downloadBtn = document.getElementById('download-btn');

analyzeBtn.addEventListener('click', () => {
    if (!isLoggedIn) {
        window.location.href = 'login.html';
        alert('Please log in to analyze files.');
        return;
    }
    if (fileInput.files.length > 0) {
        const file = fileInput.files[0];
        const reader = new FileReader();
        document.getElementById('file-name').textContent = file.name;
        document.getElementById('file-size').textContent = (file.size / 1024 / 1024).toFixed(1) + ' MB';

        reader.onload = function(e) {
            const fileData = e.target.result;
            gk_fileData[file.name] = fileData;
            if (file.name.endsWith('.xlsx')) {
                gk_isXlsx = true;
                gk_xlsxFileLookup[file.name] = true;
                const csvData = loadFileData(file.name);
                document.getElementById('file-data').textContent = csvData || 'No valid data extracted.';
                console.log('CSV Data:', csvData);
            }
            showPage('report');

            const ctxReport = document.getElementById('report-chart').getContext('2d');
            new Chart(ctxReport, {
                type: 'pie',
                data: {
                    labels: ['Trojan', 'Worm', 'Benign'],
                    datasets: [{
                        data: [70, 20, 10],
                        backgroundColor: ['#ff4d4f', '#ffeb3b', '#36b9cc']
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: { position: 'top' },
                        title: { display: true, text: 'Malware Probability Distribution' }
                    }
                }
            });
        };
        reader.readAsDataURL(file);
    } else {
        alert('Please select a file to analyze.');
    }
});

downloadBtn.addEventListener('click', () => {
    if (!isLoggedIn) {
        window.location.href = 'login.html';
        alert('Please log in to download reports.');
        return;
    }
    alert('Simulating PDF download...');
});

const urlAnalyzeBtn = document.getElementById('url-analyze-btn');
const urlInput = document.getElementById('url-input');
const urlResult = document.getElementById('url-result');

urlAnalyzeBtn.addEventListener('click', () => {
    if (!isLoggedIn) {
        window.location.href = 'login.html';
        alert('Please log in to analyze URLs.');
        return;
    }
    if (urlInput.value.trim()) {
        urlResult.classList.remove('hidden');
        document.getElementById('url-value').textContent = urlInput.value;
        document.getElementById('url-result-status').textContent = 'PHISHING ⚠️';
        document.getElementById('url-category').textContent = 'Phishing';
        document.getElementById('url-confidence').textContent = '85%';

        const ctxUrl = document.getElementById('url-chart').getContext('2d');
        new Chart(ctxUrl, {
            type: 'bar',
            data: {
                labels: ['Phishing', 'Malware', 'Redirect', 'Safe'],
                datasets: [{
                    label: 'Probability',
                    data: [85, 10, 3, 2],
                    backgroundColor: ['#ff4d4f', '#ffeb3b', '#f97316', '#36b9cc']
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { display: false },
                    title: { display: true, text: 'URL Threat Distribution' }
                },
                scales: { y: { beginAtZero: true } }
            }
        });
    } else {
        alert('Please enter a valid URL.');
    }
});

const ipAnalyzeBtn = document.getElementById('ip-analyze-btn');
const ipInput = document.getElementById('ip-input');
const ipResult = document.getElementById('ip-result');

ipAnalyzeBtn.addEventListener('click', () => {
    if (!isLoggedIn) {
        window.location.href = 'login.html';
        alert('Please log in to analyze IP addresses.');
        return;
    }
    if (ipInput.value.trim()) {
        ipResult.classList.remove('hidden');
        document.getElementById('ip-value').textContent = ipInput.value;
        document.getElementById('ip-result-status').textContent = 'BOTNET ⚠️';
        document.getElementById('ip-details').textContent = 'Associated with malicious botnet activity';
        document.getElementById('ip-confidence').textContent = '90%';
    } else {
        alert('Please enter a valid IP address.');
    }
});

const portScanBtn = document.getElementById('port-scan-btn');
const portScanInput = document.getElementById('port-scan-input');
const portScanResult = document.getElementById('port-scan-result');

portScanBtn.addEventListener('click', () => {
    if (!isLoggedIn) {
        window.location.href = 'login.html';
        alert('Please log in to perform port scans.');
        return;
    }
    if (portScanInput.value.trim()) {
        portScanResult.classList.remove('hidden');
        document.getElementById('port-scan-target').textContent = portScanInput.value;
        document.getElementById('port-scan-ports').textContent = '80 (HTTP), 443 (HTTPS)';
        document.getElementById('port-scan-services').textContent = 'Web Server (Apache/2.4.41)';
        document.getElementById('port-scan-status').textContent = 'SUSPICIOUS ⚠️';
    } else {
        alert('Please enter a valid IP or domain.');
    }
});

// Hash Analysis Logic
const hashAnalyzeBtn = document.getElementById('hash-analyze-btn');
const hashInput = document.getElementById('hash-input');
const hashResult = document.getElementById('hash-result');

if (hashAnalyzeBtn && hashInput && hashResult) {
    hashAnalyzeBtn.addEventListener('click', () => {
        if (!isLoggedIn) {
            window.location.href = 'login.html';
            alert('Please log in to analyze hashes.');
            return;
        }
        const hash = hashInput.value.trim().toLowerCase();
        if (hash) {
            const hashType = detectHashType(hash);
            hashResult.classList.remove('hidden');
            document.getElementById('hash-value').textContent = hash;
            document.getElementById('hash-type').textContent = hashType.type;
            document.getElementById('hash-details').textContent = hashType.details;
        } else {
            alert('Please enter a valid hash.');
        }
    });
}

function detectHashType(hash) {
    const hexPattern = /^[0-9a-fA-F]+$/;
    if (hash.length === 60 && (hash.startsWith('$2a$') || hash.startsWith('$2b$') || hash.startsWith('$2y$'))) {
        return { type: 'BCRYPT', details: 'Commonly used for password hashing with a salt.' };
    } else if (hash.length === 32 && hexPattern.test(hash)) {
        return { type: 'MD5/NTLM/MD4', details: '32-character hexadecimal hash, commonly MD5 or NTLM; MD4 is less common.' };
    } else if (hash.length === 40 && hexPattern.test(hash)) {
        return { type: 'SHA1', details: '40-character hexadecimal hash used in various security applications.' };
    } else if (hash.length === 64 && hexPattern.test(hash)) {
        return { type: 'SHA256', details: '64-character hexadecimal hash, widely used for secure data integrity.' };
    } else {
        return { type: 'Unknown', details: 'Hash format not recognized. Please ensure the hash is valid.' };
    }
}

// Password Strength Checker Logic
const passwordCheckBtn = document.getElementById('password-check-btn');
const passwordInput = document.getElementById('password-input');
const passwordResult = document.getElementById('password-result');

if (passwordCheckBtn && passwordInput && passwordResult) {
    passwordCheckBtn.addEventListener('click', () => {
        if (!isLoggedIn) {
            window.location.href = 'login.html';
            alert('Please log in to check passwords.');
            return;
        }
        const password = passwordInput.value.trim();
        if (password) {
            const strengthResult = checkPasswordStrength(password);
            passwordResult.classList.remove('hidden');
            document.getElementById('password-strength').textContent = strengthResult.strength;
            document.getElementById('password-strength').className = `font-bold ${strengthResult.color}`;
            document.getElementById('password-details').textContent = strengthResult.details;
        } else {
            alert('Please enter a valid password.');
        }
    });
}

function checkPasswordStrength(password) {
    let score = 0;
    let details = [];

    // Check length
    if (password.length >= 12) {
        score += 1;
        details.push('Length ≥ 12 characters (Strong).');
    } else if (password.length >= 8) {
        score += 1;
        details.push('Length 8-11 characters (Medium).');
    } else {
        details.push('Length < 8 characters (Weak).');
    }

    // Check uppercase letters
    if (/[A-Z]/.test(password)) {
        score += 1;
        details.push('Contains uppercase letters.');
    } else {
        details.push('No uppercase letters.');
    }

    // Check numbers
    if (/[0-9]/.test(password)) {
        score += 1;
        details.push('Contains numbers.');
    } else {
        details.push('No numbers.');
    }

    // Check symbols
    if (/[^A-Za-z0-9]/.test(password)) {
        score += 1;
        details.push('Contains special characters.');
    } else {
        details.push('No special characters.');
    }

    // Determine strength
    let strength, color;
    if (score >= 4) {
        strength = 'Strong';
        color = 'text-green-600';
    } else if (score >= 2) {
        strength = 'Medium';
        color = 'text-yellow-600';
    } else {
        strength = 'Weak';
        color = 'text-red-600';
    }

    return {
        strength: strength,
        details: details.join(' '),
        color: color
    };
}

// Contact Form Handling
const contactForm = document.getElementById('contact-form');
const formMessage = document.getElementById('form-message');
if (contactForm && formMessage) {
    contactForm.addEventListener('submit', (e) => {
        e.preventDefault();
        const name = document.getElementById('name').value;
        const email = document.getElementById('email').value;
        const subject = document.getElementById('subject').value;
        const message = document.getElementById('message').value;

        // Simulate form submission
        if (name && email && subject && message) {
            formMessage.classList.remove('hidden');
            formMessage.classList.add('text-green-600');
            formMessage.textContent = 'Thank you for your message! We will get back to you soon.';
            contactForm.reset();
            setTimeout(() => {
                formMessage.classList.add('hidden');
            }, 3000);
        } else {
            formMessage.classList.remove('hidden');
            formMessage.classList.add('text-red-600');
            formMessage.textContent = 'Please fill out all fields.';
        }
    });
}

// Initialize page based on localStorage
function initializePage() {
    updateNavBar();
    const savedPage = localStorage.getItem('currentPage') || 'home';
    showPage(savedPage);
}

// Run initialization on page load
initializePage();