/**
 * Email Fraud Detection Component
 * Connects to email fraud APIs on ports 8035/8022
 */
import { SERVICES, STATE } from './config.js';
import { directRequest } from './api.js';
import { showToast } from './ui.js';

async function loadEmailFraudStats() {
    try {
        const data = await directRequest(`${SERVICES.emailFraud || 'http://'+SERVER_IP+':8035'}/api/email-fraud/alerts?limit=100`);
        if (data) {
            document.getElementById('emailFraudCount').textContent = data.total || 0;
            document.getElementById('emailPhishCount').textContent = data.stats?.phishing || 0;
            document.getElementById('emailBECCount').textContent = data.stats?.bec_fraud || 0;
        }
    } catch(e) { console.log('Email fraud stats unavailable'); }
}

function cacheEmailDom() {
    // Cache email fraud specific DOM elements if needed
}

export { loadEmailFraudStats, cacheEmailDom };
