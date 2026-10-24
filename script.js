// ====== HackShield script.js (Quiz option text color fixed to white) ======

const Config = {
  APP_VERSION: '2.2.0',
  STORAGE_KEYS: {
    SCAN_HISTORY: 'hs_scan_history',
    URL_HISTORY: 'hs_url_history',
    QR_HISTORY: 'hs_qr_history',
    QUIZ_HISTORY: 'hs_quiz_history'
  }
};

// ---------- Browser Security Checks ----------
const BrowserSecurityChecks = [
  {
    id: 'https-check',
    name: 'HTTPS Connection',
    description: 'Checks whether this page is loaded over a secure, encrypted HTTPS connection.',
    fix: 'Always make sure the address bar shows "https://" and a padlock icon before entering passwords or payment details on any website.',
    danger: 'high',
    test: () => location.protocol === 'https:'
  },
  {
    id: 'sw-check',
    name: 'Offline/App Support (Service Worker)',
    description: 'Checks if your browser supports Service Workers, which allow secure offline functionality.',
    fix: 'Update to a modern browser version (Chrome, Edge, Firefox) to enable secure offline app features.',
    danger: 'low',
    test: () => 'serviceWorker' in navigator
  },
  {
    id: 'dnt-check',
    name: 'Do Not Track Signal',
    description: 'Checks if the "Do Not Track" privacy signal is enabled in your browser.',
    fix: 'Enable "Do Not Track" in your browser privacy settings (Settings → Privacy & Security → Send a "Do Not Track" request).',
    danger: 'low',
    test: () => navigator.doNotTrack === '1' || window.doNotTrack === '1'
  },
  {
    id: 'cookies-check',
    name: 'Cookie Privacy Control',
    description: 'Checks whether cookie storage is restricted in this browser, reducing tracking surface.',
    fix: 'Go to Browser Settings → Privacy → Cookies, and block third-party cookies to reduce cross-site tracking.',
    danger: 'medium',
    test: () => {
      try {
        document.cookie = '_hs_test=1';
        const hasCookie = document.cookie.indexOf('_hs_test') !== -1;
        document.cookie = '_hs_test=1; expires=Thu, 01 Jan 1970 00:00:00 UTC';
        return !hasCookie;
      } catch (e) { return true; }
    }
  },
  {
    id: 'webauthn-check',
    name: 'Secure Login Support (WebAuthn)',
    description: 'Checks whether your browser/device supports WebAuthn for passwordless, phishing-resistant authentication.',
    fix: 'Use a modern browser and enable biometric/security-key login (fingerprint, Windows Hello, etc.) where available for stronger account security.',
    danger: 'medium',
    test: () => !!(window.PublicKeyCredential)
  },
  {
    id: 'clipboard-check',
    name: 'Clipboard Access Protection',
    description: 'Checks if the Clipboard API requires explicit permission before websites can read your clipboard.',
    fix: 'Never click "Allow" on clipboard access prompts from untrusted or unfamiliar websites.',
    danger: 'medium',
    test: () => !!(navigator.clipboard && navigator.permissions)
  },
  {
    id: 'geo-check',
    name: 'Location Permission Control',
    description: 'Checks if your browser requires explicit permission before sharing your precise location.',
    fix: 'Only allow location access for trusted sites. Review and revoke unnecessary permissions in Browser Settings → Privacy → Location.',
    danger: 'medium',
    test: () => 'geolocation' in navigator && !!navigator.permissions
  },
  {
    id: 'localstorage-check',
    name: 'Local Storage Security',
    description: 'Checks if your browser supports isolated local storage per website (prevents data leaking between sites).',
    fix: 'Periodically clear site data/local storage, especially on shared or public computers, via Browser Settings → Privacy → Clear browsing data.',
    danger: 'low',
    test: () => {
      try {
        localStorage.setItem('_hs_test', '1');
        localStorage.removeItem('_hs_test');
        return true;
      } catch (e) { return false; }
    }
  }
];

// ---------- URL Scanner ----------
const URLScanner = {
  SHORTENERS: ['bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','is.gd','buff.ly','adf.ly','shorte.st'],
  SUSPICIOUS_TLDS: ['.xyz', '.top', '.tk', '.gq', '.ml', '.cf', '.ga', '.work', '.click', '.loan'],
  KEYWORDS: ['login','secure','account','update','verify','banking','confirm','signin','password','security'],

  scan(rawUrl) {
    let score = 0;
    const failedChecks = [];
    let url;
    try {
      url = new URL(rawUrl.match(/^https?:\/\//i) ? rawUrl : 'http://' + rawUrl);
    } catch (e) {
      return { verdict: 'Danger', score: 10, failedChecks: ['Invalid or malformed URL'] };
    }

    if (url.protocol !== 'https:') {
      score += 2;
      failedChecks.push('Not HTTPS — connection is unencrypted');
    }

    const hostname = url.hostname;
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
      score += 2;
      failedChecks.push('Uses raw IP address instead of domain');
    }

    if (rawUrl.includes('@')) {
      score += 2;
      failedChecks.push('Contains @ symbol — possible URL redirection trick');
    }

    if (this.SHORTENERS.some(s => hostname.includes(s))) {
      score += 2;
      failedChecks.push('Uses URL shortener — final destination hidden');
    }

    if (this.SUSPICIOUS_TLDS.some(tld => hostname.endsWith(tld))) {
      score += 1;
      failedChecks.push(`Suspicious TLD (${this.SUSPICIOUS_TLDS.find(tld => hostname.endsWith(tld))})`);
    }

    const subdomainCount = hostname.split('.').length - 2;
    if (subdomainCount > 2) {
      score += 1;
      failedChecks.push('Excessive subdomains');
    }

    const lowerUrl = rawUrl.toLowerCase();
    const keywordHits = this.KEYWORDS.filter(k => lowerUrl.includes(k)).length;
    if (keywordHits >= 2) {
      score += 1;
      failedChecks.push('High density of account/security keywords');
    }

    if (rawUrl.length > 75) {
      score += 1;
      failedChecks.push('Unusually long URL');
    }

    let verdict = 'Safe';
    if (score >= 6) verdict = 'Danger';
    else if (score >= 2) verdict = 'Caution';

    return { verdict, score, failedChecks };
  }
};

// ---------- UI ----------
const UI = {
  showToast(message, type = 'info') {
    const container = document.getElementById('toast-container') || (() => {
      const c = document.createElement('div');
      c.id = 'toast-container';
      c.style.position = 'fixed';
      c.style.bottom = '20px';
      c.style.right = '20px';
      c.style.zIndex = '9999';
      document.body.appendChild(c);
      return c;
    })();
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    toast.style.marginTop = '8px';
    toast.style.padding = '10px 16px';
    toast.style.borderRadius = '8px';
    toast.style.color = '#fff';
    toast.style.background = type === 'error' ? '#ff006e' : type === 'success' ? '#00d9ff' : '#b537f2';
    container.appendChild(toast);
    setTimeout(() => toast.remove(), 3000);
  },

  setButtonLoading(btn, text = 'Loading...') {
    if (!btn) return;
    btn.dataset.originalText = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = text;
  },

  resetButton(btn) {
    if (!btn) return;
    btn.disabled = false;
    if (btn.dataset.originalText) btn.innerHTML = btn.dataset.originalText;
  },

  switchView(viewId) {
    let target = document.getElementById(viewId)
      || document.getElementById('view-' + viewId)
      || document.querySelector(`[data-view-section="${viewId}"]`);

    if (!target) {
      console.warn('switchView: no matching view found for "' + viewId + '".');
      return;
    }

    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    target.classList.add('active');

    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    const navItem = document.querySelector(`.nav-item[data-view="${viewId}"]`);
    if (navItem) navItem.classList.add('active');
  },

  loadInitialState() {
    this.renderScanHistory();
    this.renderURLHistory();
    this.renderQRHistory();
    this.renderQuizHistory();
    this.renderDashboard();
  },

  renderDashboard() {
    const history = JSON.parse(localStorage.getItem(Config.STORAGE_KEYS.SCAN_HISTORY) || '[]');
    const last = history[0];
    if (!last) return;

    const scoreEl = document.getElementById('dashboard-score')
      || document.getElementById('overall-score')
      || document.getElementById('score-value');
    const threatEl = document.getElementById('dashboard-threat')
      || document.getElementById('threat-level')
      || document.getElementById('threat-value');
    const passedEl = document.getElementById('dashboard-passed')
      || document.getElementById('checks-passed')
      || document.getElementById('passed-value');
    const lastScanEl = document.getElementById('last-scan-summary')
      || document.getElementById('last-scan-text');

    let scoreSet = false, threatSet = false, passedSet = false, lastScanSet = false;

    if (scoreEl) { scoreEl.textContent = last.score + '%'; scoreSet = true; }
    if (threatEl) { threatEl.textContent = last.threatLevel; threatSet = true; }
    if (passedEl) { passedEl.textContent = `${last.passed}/8`; passedSet = true; }
    if (lastScanEl) {
      lastScanEl.textContent = `Last scan: ${last.date} — Score: ${last.score}%, Threat Level: ${last.threatLevel}`;
      lastScanSet = true;
    }

    if (!scoreSet || !threatSet || !passedSet) {
      document.querySelectorAll('.stat-card').forEach(card => {
        const text = card.textContent.toLowerCase();
        const valueEl = card.querySelector('h1, h2, h3, .stat-value, strong') || card.querySelector('*:last-child');
        if (!valueEl) return;

        if (!scoreSet && text.includes('overall score')) {
          valueEl.textContent = last.score + '%';
          scoreSet = true;
        } else if (!threatSet && text.includes('threat level')) {
          valueEl.textContent = last.threatLevel;
          threatSet = true;
        } else if (!passedSet && text.includes('checks passed')) {
          valueEl.textContent = `${last.passed}/8`;
          passedSet = true;
        }
      });
    }

    if (!lastScanSet) {
      const allTextEls = document.querySelectorAll('p, div, span');
      for (const el of allTextEls) {
        if (el.children.length === 0) {
          const t = el.textContent.trim();
          if (t.startsWith('No scans yet') || t.startsWith('Last scan:')) {
            el.textContent = `Last scan: ${last.date} — Score: ${last.score}%, Threat Level: ${last.threatLevel}`;
            lastScanSet = true;
            break;
          }
        }
      }
    }

    if (!scoreSet || !threatSet || !passedSet || !lastScanSet) {
      console.warn('renderDashboard: could not fully locate dashboard elements. Missing:',
        { scoreSet, threatSet, passedSet, lastScanSet });
    }
  },

  renderScannerChecks(results) {
    const container = document.getElementById('scanner-checks-list');
    if (!container) return;
    container.innerHTML = '';
    results.forEach(r => {
      const statusClass = r.passed ? 'status-safe' : (r.danger === 'high' ? 'status-danger' : 'status-caution');
      const item = document.createElement('div');
      item.className = `check-item ${statusClass}`;
      item.innerHTML = `
        <div class="check-header">
          <strong>${r.name}</strong>
          <span class="check-badge">${r.passed ? '✅ Passed' : '⚠️ Failed'}</span>
        </div>
        <p class="check-description">${r.description}</p>
        ${!r.passed ? `<p class="check-fix">💡 <strong>How to fix:</strong> ${r.fix}</p>` : ''}
      `;
      container.appendChild(item);
    });
  },

  async runFullScan() {
    const btn = document.getElementById('run-audit-btn');
    this.setButtonLoading(btn, 'Scanning...');
    await new Promise(res => setTimeout(res, 500));

    const results = BrowserSecurityChecks.map(check => {
      let passed = false;
      try { passed = !!check.test(); } catch (e) { passed = false; }
      return { ...check, passed };
    });

    this.renderScannerChecks(results);

    const passedCount = results.filter(r => r.passed).length;
    const score = Math.round((passedCount / results.length) * 100);
    let threatLevel = 'Low';
    if (score < 50) threatLevel = 'High';
    else if (score < 80) threatLevel = 'Medium';

    const history = JSON.parse(localStorage.getItem(Config.STORAGE_KEYS.SCAN_HISTORY) || '[]');
    history.unshift({
      date: new Date().toLocaleString(),
      score, threatLevel, passed: passedCount
    });
    localStorage.setItem(Config.STORAGE_KEYS.SCAN_HISTORY, JSON.stringify(history.slice(0, 20)));

    this.renderScanHistory();
    this.renderDashboard();
    this.resetButton(btn);
    this.showToast('Browser Security Check complete!', 'success');
  },

  renderScanHistory() {
    const list = document.getElementById('scan-history-list');
    if (!list) return;
    const history = JSON.parse(localStorage.getItem(Config.STORAGE_KEYS.SCAN_HISTORY) || '[]');
    list.innerHTML = history.length ? history.map(h =>
      `<div class="history-item">${h.date} — Score: ${h.score}%, Threat: ${h.threatLevel}</div>`
    ).join('') : '<p>No scan history yet.</p>';
  },

  renderURLHistory() {
    const list = document.getElementById('url-history-list');
    if (!list) return;
    const history = JSON.parse(localStorage.getItem(Config.STORAGE_KEYS.URL_HISTORY) || '[]');
    list.innerHTML = history.length ? history.map(h =>
      `<div class="history-item">${h.date} — ${h.url} → <strong>${h.verdict}</strong></div>`
    ).join('') : '<p>No URL scan history yet.</p>';
  },

  renderQRHistory() {
    const list = document.getElementById('qr-history-list');
    if (!list) return;
    const history = JSON.parse(localStorage.getItem(Config.STORAGE_KEYS.QR_HISTORY) || '[]');
    list.innerHTML = history.length ? history.map(h =>
      `<div class="history-item">${h.date} — ${h.type}: ${h.content.substring(0, 50)} ${h.verdict ? '→ ' + h.verdict : ''}</div>`
    ).join('') : '<p>No QR scan history yet.</p>';
  },

  renderQuizHistory() {
    const list = document.getElementById('quiz-history-list');
    if (!list) return;
    const history = JSON.parse(localStorage.getItem(Config.STORAGE_KEYS.QUIZ_HISTORY) || '[]');
    list.innerHTML = history.length ? history.map(h =>
      `<div class="history-item">${h.date} — Score: ${h.score}/${h.total}</div>`
    ).join('') : '<p>No quiz history yet.</p>';
  },

  renderQuizStart() {
    const stateDiv = document.getElementById('quiz-state');
    if (!stateDiv) return;
    stateDiv.innerHTML = `
      <h3>Ready to test your cybersecurity knowledge?</h3>
      <p>12 random questions, shuffled each time.</p>
      <button id="start-quiz-btn" class="btn-primary">Start Quiz</button>
    `;
    document.getElementById('start-quiz-btn').addEventListener('click', () => Quiz.start());
  },

  showQRStatus(msg) {
    const container = document.getElementById('qr-status-container');
    const msgEl = document.getElementById('qr-status-message');
    if (container) container.style.display = 'block';
    if (msgEl) msgEl.textContent = msg;
  },

  hideQRStatus() {
    const container = document.getElementById('qr-status-container');
    if (container) container.style.display = 'none';
  },

  bindURLScanner() {
    const btn = document.getElementById('scan-url-btn');
    const input = document.getElementById('url-input');
    if (!btn || !input) return;
    btn.addEventListener('click', () => {
      const url = input.value.trim();
      if (!url) { this.showToast('Please enter a URL', 'error'); return; }
      this.setButtonLoading(btn, 'Scanning...');
      setTimeout(() => {
        const result = URLScanner.scan(url);
        this.displayURLResult(url, result);
        const history = JSON.parse(localStorage.getItem(Config.STORAGE_KEYS.URL_HISTORY) || '[]');
        history.unshift({ date: new Date().toLocaleString(), url, verdict: result.verdict });
        localStorage.setItem(Config.STORAGE_KEYS.URL_HISTORY, JSON.stringify(history.slice(0, 20)));
        this.renderURLHistory();
        this.resetButton(btn);
      }, 400);
    });
  },

  displayURLResult(url, result) {
    const container = document.getElementById('url-result-container');
    const card = document.getElementById('url-result-card');
    if (!container || !card) return;
    container.style.display = 'block';
    const verdictClass = `verdict-${result.verdict.toLowerCase()}`;
    const reasonsHtml = result.failedChecks.length
      ? `<ul>${result.failedChecks.map(f => `<li>${f}</li>`).join('')}</ul>`
      : '<p>No obvious warning signs detected.</p>';
    card.innerHTML = `
      <span class="verdict-badge ${verdictClass}">${result.verdict}</span>
      <p><strong>URL:</strong> ${url}</p>
      ${reasonsHtml}
    `;
  },

  bindQRScanner() {
    const btn = document.getElementById('qr-upload-btn');
    const fileInput = document.getElementById('qr-file-input');
    if (!btn || !fileInput) return;
    btn.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', (e) => {
      const file = e.target.files[0];
      if (file) QRScanner.processImage(file);
      fileInput.value = '';
    });
  },

  displayQRResult(type, content, verdictResult) {
    const container = document.getElementById('qr-result-container');
    const card = document.getElementById('qr-result-card');
    if (!container || !card) return;
    container.style.display = 'block';
    let html = `<p><strong>Type:</strong> ${type}</p><p><strong>Content:</strong> ${content}</p>`;
    if (verdictResult) {
      const verdictClass = `verdict-${verdictResult.verdict.toLowerCase()}`;
      const reasonsHtml = verdictResult.failedChecks.length
        ? `<ul>${verdictResult.failedChecks.map(f => `<li>${f}</li>`).join('')}</ul>`
        : '<p>No obvious warning signs detected.</p>';
      html += `<span class="verdict-badge ${verdictClass}">${verdictResult.verdict}</span>${reasonsHtml}`;
    }
    card.innerHTML = html;
  },

  bindHistoryControls() {
    const bind = (btnId, renderFn) => {
      const refreshBtn = document.getElementById(btnId);
      if (refreshBtn) refreshBtn.addEventListener('click', () => { renderFn.call(this); this.showToast('Refreshed', 'success'); });
    };
    bind('refresh-scan-history', this.renderScanHistory);
    bind('refresh-url-history', this.renderURLHistory);
    bind('refresh-qr-history', this.renderQRHistory);
    bind('refresh-quiz-history', this.renderQuizHistory);

    const bindClear = (btnId, storageKey, renderFn) => {
      const clearBtn = document.getElementById(btnId);
      if (clearBtn) clearBtn.addEventListener('click', () => {
        localStorage.removeItem(storageKey);
        renderFn.call(this);
        this.showToast('History cleared', 'success');
      });
    };
    bindClear('clear-scan-history', Config.STORAGE_KEYS.SCAN_HISTORY, this.renderScanHistory);
    bindClear('clear-url-history', Config.STORAGE_KEYS.URL_HISTORY, this.renderURLHistory);
    bindClear('clear-qr-history', Config.STORAGE_KEYS.QR_HISTORY, this.renderQRHistory);
  }
};

// ---------- Quiz ----------
const QuizBank = [
  { q: 'What does HTTPS provide that HTTP does not?', options: ['Faster loading', 'Encryption', 'Better design', 'More ads'], answer: 1 },
  { q: 'What is phishing?', options: ['A type of virus', 'Fraudulent attempt to get sensitive info', 'A firewall setting', 'A backup method'], answer: 1 },
  { q: 'What makes a password strong?', options: ['Your birthday', 'Length and complexity', 'Your name', 'Using "password123"'], answer: 1 },
  { q: 'What is two-factor authentication (2FA)?', options: ['Two passwords', 'An extra verification step beyond password', 'Two accounts', 'A type of virus'], answer: 1 },
  { q: 'What should you do with suspicious email links?', options: ['Click immediately', 'Forward to friends', 'Avoid clicking and verify sender', 'Reply with your password'], answer: 2 },
  { q: 'What is a VPN used for?', options: ['Speeding up internet', 'Encrypting and masking your connection', 'Blocking ads', 'Downloading files faster'], answer: 1 },
  { q: 'What is malware?', options: ['Malicious software', 'A type of hardware', 'An antivirus brand', 'A browser extension'], answer: 0 },
  { q: 'Why avoid public Wi-Fi for banking?', options: ['It is slow', 'Data can be intercepted', 'It costs money', 'It uses more battery'], answer: 1 },
  { q: 'What is a strong indicator of a phishing site?', options: ['HTTPS padlock', 'Urgent threatening language', 'Clean design', 'Fast loading'], answer: 1 },
  { q: 'What does a firewall do?', options: ['Speeds up Wi-Fi', 'Filters network traffic for threats', 'Stores passwords', 'Backs up files'], answer: 1 },
  { q: 'What is social engineering?', options: ['Coding social media apps', 'Manipulating people into revealing info', 'A networking protocol', 'A design pattern'], answer: 1 },
  { q: 'What should you do after a data breach notice?', options: ['Ignore it', 'Change affected passwords immediately', 'Delete your account', 'Wait a few months'], answer: 1 },
  { q: 'What is ransomware?', options: ['Free antivirus', 'Malware that locks data for ransom', 'A browser plugin', 'A firewall type'], answer: 1 },
  { q: 'Why use a password manager?', options: ['To slow down login', 'To securely generate/store unique passwords', 'To share passwords publicly', 'It is required by law'], answer: 1 },
  { q: 'What is the purpose of software updates?', options: ['Add ads', 'Fix security vulnerabilities', 'Slow down your device', 'Change the logo'], answer: 1 },
  { q: 'What is a brute-force attack?', options: ['Physically breaking a device', 'Repeatedly guessing passwords', 'A type of virus scan', 'A firewall rule'], answer: 1 },
  { q: 'What does "HTTPS padlock" guarantee?', options: ['The site is 100% safe', 'The connection is encrypted', 'No malware exists', 'The site is government verified'], answer: 1 },
  { q: 'What is the safest way to verify a bank email?', options: ['Click the link in the email', 'Call the bank using an official number', 'Reply to the email', 'Forward it to friends'], answer: 1 }
];

const Quiz = {
  questions: [],
  currentIndex: 0,
  score: 0,

  start() {
    const shuffled = [...QuizBank].sort(() => Math.random() - 0.5).slice(0, 12);
    this.questions = shuffled.map(q => {
      const options = q.options.map((opt, i) => ({ text: opt, isCorrect: i === q.answer }));
      options.sort(() => Math.random() - 0.5);
      return { q: q.q, options };
    });
    this.currentIndex = 0;
    this.score = 0;
    this.render();
  },

  render() {
    const stateDiv = document.getElementById('quiz-state');
    if (!stateDiv) return;
    if (this.currentIndex >= this.questions.length) { this.finish(); return; }
    const current = this.questions[this.currentIndex];
    stateDiv.innerHTML = `
      <p class="quiz-progress">Question ${this.currentIndex + 1} of ${this.questions.length}</p>
      <h3>${current.q}</h3>
      <div class="quiz-options">
        ${current.options.map((opt, i) => `<button class="quiz-option" data-index="${i}" style="color:#ffffff;">${opt.text}</button>`).join('')}
      </div>
      <button id="exit-quiz-btn" class="btn-secondary">Exit Quiz</button>
    `;
    stateDiv.querySelectorAll('.quiz-option').forEach(btn => {
      btn.addEventListener('click', () => this.answer(parseInt(btn.dataset.index)));
    });
    document.getElementById('exit-quiz-btn').addEventListener('click', () => this.exitQuiz());
  },

  answer(selectedIndex) {
    const current = this.questions[this.currentIndex];
    const buttons = document.querySelectorAll('.quiz-option');
    buttons.forEach(btn => btn.disabled = true);
    buttons.forEach((btn, i) => {
      if (current.options[i].isCorrect) {
        btn.classList.add('correct');
        btn.style.color = '#ffffff';
      } else if (i === selectedIndex) {
        btn.classList.add('incorrect');
        btn.style.color = '#ffffff';
      }
    });
    if (current.options[selectedIndex].isCorrect) this.score++;
    setTimeout(() => {
      this.currentIndex++;
      this.render();
    }, 900);
  },

  finish() {
    const history = JSON.parse(localStorage.getItem(Config.STORAGE_KEYS.QUIZ_HISTORY) || '[]');
    history.unshift({ date: new Date().toLocaleString(), score: this.score, total: this.questions.length });
    localStorage.setItem(Config.STORAGE_KEYS.QUIZ_HISTORY, JSON.stringify(history.slice(0, 20)));
    UI.renderQuizHistory();
    this.renderResults();
  },

  renderResults() {
    const stateDiv = document.getElementById('quiz-state');
    if (!stateDiv) return;
    stateDiv.innerHTML = `
      <h3>Quiz Complete!</h3>
      <p>You scored ${this.score} out of ${this.questions.length}</p>
      <button id="retry-quiz-btn" class="btn-primary">Try Again</button>
    `;
    document.getElementById('retry-quiz-btn').addEventListener('click', () => this.start());
  },

  exitQuiz() {
    this.currentIndex = 0;
    this.score = 0;
    this.questions = [];
    UI.renderQuizStart();
  }
};

// ---------- QR Scanner ----------
const QRScanner = {
  isUrlString(str) {
    try { new URL(str); return true; } catch (e) { return false; }
  },

  async processImage(file) {
    UI.showQRStatus('📤 Loading image...');
    await new Promise(res => setTimeout(res, 400));

    const reader = new FileReader();
    reader.onload = (e) => {
      const img = new Image();
      img.onload = async () => {
        UI.showQRStatus('🔍 Scanning QR code...');
        await new Promise(res => setTimeout(res, 400));

        const canvas = document.createElement('canvas');
        canvas.width = img.width;
        canvas.height = img.height;
        const ctx = canvas.getContext('2d');
        ctx.drawImage(img, 0, 0);
        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const code = jsQR(imageData.data, imageData.width, imageData.height);

        if (!code) {
          UI.hideQRStatus();
          UI.showToast('⚠️ No QR code found in this image', 'error');
          return;
        }

        const content = code.data;
        let type = 'Text';
        let verdictResult = null;

        if (this.isUrlString(content)) {
          type = 'URL';
          UI.showQRStatus('🔗 Checking link safety...');
          await new Promise(res => setTimeout(res, 400));
          verdictResult = URLScanner.scan(content);
        } else if (content.startsWith('WIFI:')) {
          type = 'Wi-Fi';
        } else if (content.startsWith('mailto:')) {
          type = 'Email';
        } else if (content.startsWith('tel:')) {
          type = 'Phone';
        } else if (content.startsWith('BEGIN:VCARD')) {
          type = 'Contact';
        }

        UI.hideQRStatus();
        UI.displayQRResult(type, content, verdictResult);
        this.saveHistory({ type, content, verdict: verdictResult ? verdictResult.verdict : null });
      };
      img.src = e.target.result;
    };
    reader.readAsDataURL(file);
  },

  saveHistory(result) {
    const history = JSON.parse(localStorage.getItem(Config.STORAGE_KEYS.QR_HISTORY) || '[]');
    history.unshift({ date: new Date().toLocaleString(), ...result });
    localStorage.setItem(Config.STORAGE_KEYS.QR_HISTORY, JSON.stringify(history.slice(0, 20)));
    UI.renderQRHistory();
  }
};

// ---------- Init ----------
document.addEventListener('DOMContentLoaded', () => {
  UI.loadInitialState();
  UI.renderQuizStart();

  document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', () => {
      const view = item.dataset.view;
      if (view) UI.switchView(view);
    });
  });

  const runAuditBtn = document.getElementById('run-audit-btn');
  if (runAuditBtn) runAuditBtn.addEventListener('click', () => UI.runFullScan());

  UI.bindURLScanner();
  UI.bindQRScanner();
  UI.bindHistoryControls();

  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('./sw.js').catch(() => {});
  }
});