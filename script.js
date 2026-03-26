document.addEventListener('DOMContentLoaded', () => {
    const scanBtn = document.getElementById('scanBtn');
    const resetBtn = document.getElementById('resetBtn');
    const copyBtn = document.getElementById('copyBtn');
    const emailInput = document.getElementById('emailInput');
    
    const scannerSection = document.getElementById('scannerSection');
    const loadingSection = document.getElementById('loadingSection');
    const resultsSection = document.getElementById('resultsSection');
    
    const scoreText = document.getElementById('scoreText');
    const progressCircle = document.getElementById('progressCircle');
    const statusBadge = document.getElementById('statusBadge');
    const badgeText = document.getElementById('badgeText');
    const badgeIcon = document.getElementById('badgeIcon');
    
    const aiExplanation = document.getElementById('aiExplanation');
    const flagsList = document.getElementById('flagsList');
    const highlightedContent = document.getElementById('highlightedContent');
    const scanCompleteSound = document.getElementById('scanCompleteSound');

    // --- ICONS & STYLING ---
    const ICONS = {
        safe: `<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>`,
        warn: `<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>`,
        danger: `<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>`
    };

    // --- ENHANCED PHISHING DETECTION CONSTANTS ---
    const KEYWORDS = {
        CRITICAL: [
            'urgent', 'immediate action', 'suspended', 'unauthorized access',
            'verify now', 'security alert', 'password reset required', 'account locked',
            'confirm identity', 'restricted access', 'official notice', 'legal action'
        ],
        SCAM: [
            'win', 'winner', 'prize', 'gift card', 'lottery', 'inheritance',
            'earn money', 'investment opportunity', 'guaranteed return', 'claim reward',
            'exclusive offer', 'be rewarded', 'act now before it’s gone'
        ],
        FINANCIAL: [
            'wire transfer', 'payment pending', 'invoice attached', 'refund status',
            'billing department', 'bank details', 'transaction id', 'tax return',
            'crypto', 'bitcoin', 'wallet update'
        ],
        SPOOFING: [
            'amaz0n', 'paypaI', 'googIe', 'microsoft-support', 'appleid-login',
            'netflix-update', 'chase-security', 'wellsfargo-verify', 'binance-lock'
        ]
    };

    const SUSPICIOUS_TLDS = ['.xyz', '.top', '.icu', '.work', '.click', '.date', '.loan', '.tk', '.ml', '.ga', '.cf'];
    const LINK_PATTERN = /https?:\/\/[^\s,!.?()\[\]{}'"]+/g;
    
    // Magnetic Button Effect
    scanBtn.addEventListener('mousemove', (e) => {
        const rect = scanBtn.getBoundingClientRect();
        const x = e.clientX - rect.left - rect.width / 2;
        const y = e.clientY - rect.top - rect.height / 2;
        scanBtn.style.transform = `translate(${x * 0.15}px, ${y * 0.25}px) scale(1.02)`;
    });

    scanBtn.addEventListener('mouseleave', () => {
        scanBtn.style.transform = '';
    });

    scanBtn.addEventListener('click', () => {
        const text = emailInput.value.trim();
        if (!text) {
            showToast('NEURAL ERROR: Input content missing');
            return;
        }
        
        scannerSection.classList.add('hidden');
        loadingSection.classList.remove('hidden');
        resultsSection.classList.add('hidden');
        window.scrollTo({ top: 0, behavior: 'smooth' });

        // Simulate Advanced Analysis
        setTimeout(() => {
            analyzeEmail(text);
            scanCompleteSound.volume = 0.1;
            scanCompleteSound.play().catch(() => {});
        }, 3000); // 3 seconds for better futuristic feel
    });

    resetBtn.addEventListener('click', () => {
        resultsSection.classList.add('hidden');
        scannerSection.classList.remove('hidden');
        emailInput.value = '';
        emailInput.focus();
        progressCircle.style.strokeDashoffset = 251.2;
    });

    copyBtn.addEventListener('click', () => {
        const score = scoreText.innerText;
        const status = badgeText.innerText;
        const explanation = aiExplanation.innerText;
        const report = `NEXUS SHIELD THREAT REPORT\n---------------------------\nScore: ${score}%\nStatus: ${status}\n\nAnalysis Result:\n${explanation}`;
        navigator.clipboard.writeText(report).then(() => {
            showToast('ANALYSIS COPIED TO SYSTEM CLIPBOARD');
        });
    });

    function analyzeEmail(text) {
        let score = 0;
        let flags = [];
        let parsedHtml = text;
        const normalizedText = text.toLowerCase();

        // 1. ADVANCED LINK HEURISTICS
        const links = text.match(LINK_PATTERN) || [];
        if (links.length > 0) {
            let maliciousLinksCount = 0;
            links.forEach(link => {
                let linkRisk = 0;
                const lowLink = link.toLowerCase();
                
                if (link.startsWith('http://')) linkRisk += 20; // Rule: Unsecured
                if (SUSPICIOUS_TLDS.some(tld => lowLink.includes(tld))) linkRisk += 30; // Rule: Suspicious TLD
                if (lowLink.split('.').length > 4) linkRisk += 25; // Rule: Deep Subdomain

                // Rule: Homoglyph / Fake Char Detection
                if (lowLink.includes('0') || lowLink.includes('i')) {
                    const domainPart = lowLink.split('/')[2] || '';
                    if (domainPart.match(/[0i]/)) linkRisk += 35;
                }

                if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(link)) linkRisk += 45; // Rule: Raw IP

                if (linkRisk > 0) {
                    maliciousLinksCount++;
                    score += linkRisk;
                    // Wrap with highlight
                    const escapedLink = link.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
                    const linkRegex = new RegExp(escapedLink, 'g');
                    parsedHtml = parsedHtml.replace(linkRegex, `<span class="hl-danger">$&</span>`);
                }
            });

            if (maliciousLinksCount > 0) {
                flags.push(`SYSTEM ALERT: ${maliciousLinksCount} malicious URL signatures found`);
            } else {
                score += 8;
                flags.push('Low-risk URL presence detected');
            }
        }

        // 2. MULTI-CATEGORY TRIGGER ANALYSIS
        // Critical / Urgency
        KEYWORDS.CRITICAL.forEach(kw => {
            const regex = new RegExp(`\\b${kw}\\b`, 'gi');
            if (regex.test(text)) {
                score += 25;
                flags.push(`Threat Signature: "${kw.toUpperCase()}" (URGENCY)`);
                parsedHtml = parsedHtml.replace(regex, `<span class="hl-danger">$&</span>`);
            }
        });

        // Scam / Reward
        KEYWORDS.SCAM.forEach(kw => {
            const regex = new RegExp(`\\b${kw}\\b`, 'gi');
            if (regex.test(text)) {
                score += 15;
                flags.push(`Scam Vector: "${kw.toUpperCase()}"`);
                parsedHtml = parsedHtml.replace(regex, `<span class="hl-warn">$&</span>`);
            }
        });

        // Financial Hooks
        KEYWORDS.FINANCIAL.forEach(kw => {
            const regex = new RegExp(`\\b${kw}\\b`, 'gi');
            if (regex.test(text)) {
                score += 12;
                flags.push(`Financial Hook: "${kw.toUpperCase()}"`);
                parsedHtml = parsedHtml.replace(regex, `<span class="hl-warn">$&</span>`);
            }
        });

        // Advanced Brand Spoofing Check (Highest Weight)
        KEYWORDS.SPOOFING.forEach(kw => {
            const regex = new RegExp(`\\b${kw}\\b`, 'gi');
            if (regex.test(normalizedText)) {
                score += 45;
                flags.push(`CRITICAL ALERT: BRAND SPOOFING ATTEMPT ("${kw}")`);
                // Match the original case for replacement
                const originalMatchRegex = new RegExp(`(${kw})`, 'gi');
                parsedHtml = parsedHtml.replace(originalMatchRegex, `<span class="hl-danger">$1</span>`);
            }
        });

        // 3. AGGREGATE RISK SCORE CALCULATION
        score = Math.min(score, 99);
        if (score === 0 && text.length > 0) {
            if (text.length < 40) score = 10; // Rule: Too short suspect
            else score = Math.floor(Math.random() * 5) + 2; // Baseline
        }

        // --- FINAL ASSESSMENT LOGIC ---
        let status = 'safe';
        let label = 'SAFE';
        let explanation = 'Neural analysis complete. No significant threat vectors found. This communication aligns with standard safe protocols and should be safe for normal engagement.';

        if (score > 65) {
            status = 'danger';
            label = 'DANGEROUS';
            explanation = 'CRITICAL WARNING. Our system has detected a high-confidence phishing attempt. The message contains multiple malicious signatures including brand spoofing, anomalous links, and extreme psychological pressure. DO NOT ENGAGE.';
        } else if (score >= 20) {
            status = 'warn';
            label = 'SUSPICIOUS';
            explanation = 'CAUTION ADVISED. Detected moderate-risk elements often associated with marketing spam or social engineering lurs. While not definitively malicious, you should verify the sender identity before clicking links.';
        }
        
        if (flags.length === 0) flags.push('No suspicious neural flags triggered');

        // Only show top 5 relevant flags to keep UI clean
        renderResults(score, status, label, explanation, flags.slice(0, 5), parsedHtml);
    }

    function renderResults(score, status, label, explanation, flags, parsedHtml) {
        loadingSection.classList.add('hidden');
        resultsSection.classList.remove('hidden');

        scoreText.innerText = '0'; // For counter animation
        badgeText.innerText = label;
        badgeIcon.innerHTML = ICONS[status];
        statusBadge.className = `status-badge ${status}`;
        
        aiExplanation.innerText = explanation;
        highlightedContent.innerHTML = parsedHtml;

        // Render Staggered Flag List
        flagsList.innerHTML = '';
        flags.forEach((flag, index) => {
            const li = document.createElement('li');
            li.innerHTML = `<span style="color:var(--text-muted);margin-right:8px">●</span> ${flag}`;
            flagsList.appendChild(li);
            setTimeout(() => li.classList.add('visible'), 150 * index);
        });

        animateValue(scoreText, 0, score, 2000);
        
        const totalOffset = 251.2;
        const offset = totalOffset - (score / 100) * totalOffset;
        
        const scorePanel = document.querySelector('.score-panel');
        scorePanel.className = `score-panel glass-panel theme-${status}`;
        
        setTimeout(() => {
            progressCircle.style.stroke = `var(--current-clr)`;
            progressCircle.style.strokeDashoffset = offset;
        }, 100);
    }

    function animateValue(obj, start, end, duration) {
        let startTimestamp = null;
        const step = (timestamp) => {
            if (!startTimestamp) startTimestamp = timestamp;
            const progress = Math.min((timestamp - startTimestamp) / duration, 1);
            obj.innerHTML = Math.floor(progress * (end - start) + start);
            if (progress < 1) window.requestAnimationFrame(step);
        };
        window.requestAnimationFrame(step);
    }

    function showToast(msg) {
        const toast = document.createElement('div');
        toast.className = 'toast-notification';
        toast.style.position = 'fixed';
        toast.style.bottom = '2rem';
        toast.style.left = '50%';
        toast.style.transform = 'translateX(-50%)';
        toast.style.background = 'linear-gradient(135deg, var(--accent-color), var(--electric-indigo))';
        toast.style.color = 'white';
        toast.style.padding = '1rem 3rem';
        toast.style.borderRadius = '16px';
        toast.style.fontWeight = '800';
        toast.style.letterSpacing = '1px';
        toast.style.boxShadow = '0 10px 30px rgba(0,0,0,0.5)';
        toast.style.zIndex = '10000';
        toast.style.fontFamily = 'var(--font-heading)';
        toast.style.animation = 'fadeInUp 0.3s ease-out';
        toast.innerText = msg;
        document.body.appendChild(toast);
        setTimeout(() => toast.remove(), 4000);
    }
});
