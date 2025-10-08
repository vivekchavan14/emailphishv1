// Fixed Phishing Alert System with Working Dropdown - Smaller Size
console.log('🎯 Loading Fixed Popup System with Working Dropdown...');

class FixedPhishingAlert {
    constructor() {
        this.alertTypes = {
            UNSAFE: {
                threshold: 50, // 50% threshold - anything above is considered unsafe
                class: 'unsafe-email',
                color: '#dc2626',
                bgColor: 'linear-gradient(135deg, #fef2f2, #fee2e2)',
                borderColor: '#dc2626',
                icon: '🛡️',
                title: 'UNSAFE EMAIL DETECTED',
                subtitle: 'This email appears to be suspicious',
                autoCloseDelay: 10000
            },
            SAFE: {
                threshold: 0,
                class: 'safe-email',
                color: '#059669',
                bgColor: 'linear-gradient(135deg, #f0fdf4, #dcfce7)',
                borderColor: '#059669',
                icon: '✅',
                title: 'SAFE EMAIL',
                subtitle: 'This email appears legitimate',
                autoCloseDelay: 5000
            }
        };
        
        this.injectStyles();
    }

    injectStyles() {
        if (document.getElementById('fixed-phishing-alert-styles')) return;
        
        const styles = document.createElement('style');
        styles.id = 'fixed-phishing-alert-styles';
        styles.textContent = `
            /* Fixed Phishing Alert System - Smaller & Working Dropdown */
            .fixed-phishing-alert {
                position: fixed;
                top: 20px;
                right: 20px;
                z-index: 9999999;
                width: 320px;
                max-width: calc(100vw - 40px);
                background: white;
                border-radius: 12px;
                box-shadow: 0 20px 40px rgba(0, 0, 0, 0.15), 0 8px 16px rgba(0, 0, 0, 0.1);
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                overflow: hidden;
                animation: slideInAlert 0.5s cubic-bezier(0.16, 1, 0.3, 1);
                border: 1px solid rgba(0, 0, 0, 0.06);
            }

            .fixed-phishing-alert.unsafe-email {
                border-left: 5px solid #dc2626;
                box-shadow: 0 20px 40px rgba(220, 38, 38, 0.25), 0 8px 16px rgba(220, 38, 38, 0.15);
            }

            .fixed-phishing-alert.safe-email {
                border-left: 5px solid #059669;
                box-shadow: 0 20px 40px rgba(5, 150, 105, 0.2), 0 8px 16px rgba(5, 150, 105, 0.1);
            }

            .fixed-alert-header {
                padding: 16px;
                display: flex;
                align-items: center;
                gap: 12px;
                position: relative;
                border-bottom: 1px solid rgba(0, 0, 0, 0.04);
            }

            .fixed-alert-icon {
                font-size: 24px;
                line-height: 1;
                animation: iconPulse 2s ease-in-out infinite;
            }

            .fixed-alert-content {
                flex: 1;
                min-width: 0;
            }

            .fixed-alert-title {
                font-size: 14px;
                font-weight: 700;
                letter-spacing: 0.1px;
                margin: 0 0 4px 0;
                line-height: 1.2;
            }

            .fixed-alert-subtitle {
                font-size: 12px;
                font-weight: 500;
                margin: 0 0 6px 0;
                opacity: 0.8;
            }

            .fixed-alert-percentage {
                display: inline-flex;
                align-items: center;
                gap: 4px;
                font-size: 11px;
                font-weight: 600;
                padding: 4px 8px;
                border-radius: 12px;
                color: white;
                margin-top: 2px;
            }

            .fixed-alert-close {
                position: absolute;
                top: 12px;
                right: 12px;
                background: rgba(0, 0, 0, 0.1);
                border: none;
                border-radius: 50%;
                width: 28px;
                height: 28px;
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 16px;
                color: rgba(0, 0, 0, 0.6);
                cursor: pointer;
                transition: all 0.2s ease;
            }

            .fixed-alert-close:hover {
                background: rgba(0, 0, 0, 0.15);
                color: rgba(0, 0, 0, 0.8);
                transform: scale(1.1);
            }

            .fixed-dropdown-toggle {
                width: 100%;
                padding: 12px 16px;
                background: rgba(0, 0, 0, 0.02);
                border: none;
                border-top: 1px solid rgba(0, 0, 0, 0.06);
                font-size: 13px;
                font-weight: 600;
                cursor: pointer;
                transition: all 0.3s ease;
                color: #6b7280;
                display: flex;
                align-items: center;
                justify-content: center;
                gap: 6px;
            }

            .fixed-dropdown-toggle:hover {
                background: rgba(0, 0, 0, 0.05);
                color: #374151;
            }

            .fixed-dropdown-toggle.expanded {
                background: rgba(0, 0, 0, 0.05);
                color: #374151;
            }

            .fixed-dropdown-arrow {
                transition: transform 0.3s ease;
                font-size: 10px;
                display: inline-block;
            }

            .fixed-dropdown-toggle.expanded .fixed-dropdown-arrow {
                transform: rotate(180deg);
            }

            .fixed-dropdown-content {
                max-height: 0;
                overflow: hidden;
                transition: max-height 0.4s cubic-bezier(0.4, 0, 0.2, 1), opacity 0.3s ease;
                background: #fafafa;
                opacity: 0;
            }

            .fixed-dropdown-content.expanded {
                max-height: 400px;
                opacity: 1;
            }

            .fixed-risk-assessment {
                padding: 14px;
                border-left: 3px solid currentColor;
                margin: 12px;
                border-radius: 8px;
                background: rgba(255, 255, 255, 0.7);
            }

            .fixed-risk-header {
                display: flex;
                align-items: center;
                gap: 8px;
                margin-bottom: 8px;
            }

            .fixed-risk-indicator {
                width: 12px;
                height: 12px;
                border-radius: 50%;
                flex-shrink: 0;
            }

            .fixed-risk-title {
                font-size: 14px;
                font-weight: 700;
                margin: 0;
            }

            .fixed-risk-text {
                font-size: 12px;
                line-height: 1.5;
                margin: 0;
                font-weight: 500;
            }

            .fixed-risk-bars {
                padding: 0 14px 14px 14px;
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 16px;
            }

            .fixed-risk-bar {
                text-align: center;
            }

            .fixed-risk-bar-label {
                font-size: 11px;
                font-weight: 700;
                margin-bottom: 8px;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }

            .fixed-risk-bar-container {
                background: rgba(0, 0, 0, 0.1);
                height: 6px;
                border-radius: 4px;
                overflow: hidden;
                margin-bottom: 8px;
                position: relative;
            }

            .fixed-risk-bar-fill {
                height: 100%;
                border-radius: 4px;
                transition: width 1.2s cubic-bezier(0.4, 0, 0.2, 1);
                position: relative;
            }

            .fixed-risk-bar-fill.phishing {
                background: linear-gradient(90deg, #ef4444, #dc2626);
            }

            .fixed-risk-bar-fill.safe {
                background: linear-gradient(90deg, #10b981, #059669);
            }

            .fixed-risk-percentage {
                font-size: 16px;
                font-weight: 700;
                margin-top: 2px;
            }

            .fixed-analysis-details {
                padding: 0 14px 14px 14px;
            }

            .fixed-analysis-header {
                display: flex;
                align-items: center;
                gap: 8px;
                margin-bottom: 12px;
            }

            .fixed-analysis-title {
                font-size: 14px;
                font-weight: 700;
                margin: 0;
            }

            .fixed-reasons-list {
                display: grid;
                gap: 8px;
            }

            .fixed-reason-item {
                display: flex;
                align-items: flex-start;
                gap: 10px;
                padding: 10px 12px;
                background: rgba(255, 255, 255, 0.8);
                border-radius: 8px;
                border: 1px solid rgba(0, 0, 0, 0.04);
                transition: all 0.2s ease;
                animation: fadeInUp 0.4s ease;
                animation-fill-mode: both;
            }

            .fixed-reason-item:hover {
                background: rgba(255, 255, 255, 1);
                transform: translateY(-1px);
                box-shadow: 0 3px 8px rgba(0, 0, 0, 0.1);
            }

            .fixed-reason-bullet {
                width: 6px;
                height: 6px;
                border-radius: 50%;
                background: currentColor;
                margin-top: 6px;
                flex-shrink: 0;
            }

            .fixed-reason-text {
                flex: 1;
                font-size: 12px;
                line-height: 1.4;
                font-weight: 500;
                margin: 0;
            }

            /* Animations */
            @keyframes slideInAlert {
                0% {
                    opacity: 0;
                    transform: translateX(100%) scale(0.95);
                }
                100% {
                    opacity: 1;
                    transform: translateX(0) scale(1);
                }
            }

            @keyframes iconPulse {
                0%, 100% { transform: scale(1); }
                50% { transform: scale(1.05); }
            }

            @keyframes fadeInUp {
                0% {
                    opacity: 0;
                    transform: translateY(8px);
                }
                100% {
                    opacity: 1;
                    transform: translateY(0);
                }
            }

            /* Responsive Design */
            @media (max-width: 640px) {
                .fixed-phishing-alert {
                    width: calc(100vw - 20px);
                    right: 10px;
                    top: 10px;
                }
                
                .fixed-risk-bars {
                    grid-template-columns: 1fr;
                    gap: 12px;
                }
            }
        `;
        
        document.head.appendChild(styles);
    }

    getAlertType(phishingPercentage) {
        console.log('🎯 PhishMail Guard: Checking alert type for', phishingPercentage + '% phishing risk');
        if (phishingPercentage >= 50) {
            console.log('🔴 Alert Type: UNSAFE (>=50%)');
            return this.alertTypes.UNSAFE;
        }
        console.log('🟢 Alert Type: SAFE (<50%)');
        return this.alertTypes.SAFE;
    }

    generateReasons(result, phishingPercentage) {
        const reasons = [];
        
        // Add user-friendly reasons from API if available, otherwise use our own
        if (result.reasons && result.reasons.length > 0) {
            // Transform technical reasons into user-friendly ones
            result.reasons.forEach(reason => {
                reasons.push(this.makeReasonUserFriendly(reason));
            });
        }
        
        // Add context-appropriate user-friendly reasons
        if (phishingPercentage >= 50) {
            // UNSAFE email reasons - clear and actionable
            const unsafeReasons = [
                'This email contains suspicious language patterns',
                'The sender may not be who they claim to be',
                'Links or requests in this email could be dangerous',
                'This email uses tactics common in scam attempts',
                'We recommend not clicking any links in this email',
                'Be very careful before sharing any personal information'
            ];
            // Add some of these if we don't have enough specific reasons
            while (reasons.length < 4 && unsafeReasons.length > 0) {
                reasons.push(unsafeReasons.shift());
            }
        } else {
            // SAFE email reasons - reassuring but still educational
            const safeReasons = [
                'This email appears to be from a legitimate source',
                'No suspicious patterns or dangerous links detected',
                'The email format and language appear professional',
                'Security analysis found no major red flags',
                'This email is likely safe to read and respond to',
                'Continue using normal email safety practices'
            ];
            // Add some of these if we don't have enough specific reasons
            while (reasons.length < 3 && safeReasons.length > 0) {
                reasons.push(safeReasons.shift());
            }
        }
        
        return reasons.slice(0, 4); // Limit to 4 clear, actionable reasons
    }
    
    makeReasonUserFriendly(technicalReason) {
        // Convert technical reasons to user-friendly language
        const friendlyMappings = {
            'ML model detected phishing patterns': 'Our security system detected suspicious patterns',
            'Contains urgent action indicators': 'This email uses urgent language to pressure you',
            'Contains credential theft patterns': 'This email may be trying to steal your passwords',
            'Contains threat language patterns': 'This email uses threatening language',
            'Contains financial scam patterns': 'This email may be a financial scam',
            'Contains fake security patterns': 'This email may be faking security alerts',
            'Excessive use of exclamation marks': 'This email uses too many exclamation marks (common in scams)',
            'Excessive use of capital letters': 'This email uses excessive CAPITAL LETTERS',
            'Contains suspicious URLs': 'This email contains suspicious links',
            'References known legitimate services': 'This email mentions legitimate companies you may trust',
            'Uses professional language patterns': 'This email uses professional, business-like language',
            'Contains legitimate business terms': 'This email uses normal business terminology'
        };
        
        // Check for partial matches and return friendly version
        for (const [technical, friendly] of Object.entries(friendlyMappings)) {
            if (technicalReason.toLowerCase().includes(technical.toLowerCase())) {
                return friendly;
            }
        }
        
        // If no mapping found, return the original but make it more user-friendly
        return technicalReason.charAt(0).toUpperCase() + technicalReason.slice(1).toLowerCase();
    }

    getRiskAssessmentText(phishingPercentage) {
        if (phishingPercentage >= 50) {
            return 'UNSAFE EMAIL: This email appears to be suspicious and may be a phishing attempt. We recommend not clicking any links, downloading attachments, or sharing personal information. If you think this email should be legitimate, verify directly with the sender through a different method.';
        } else {
            return 'SAFE EMAIL: This email appears to be legitimate and poses low risk. While it\'s likely safe to interact with, always use good email security practices like verifying unexpected requests and being cautious with personal information.';
        }
    }

    toggleDropdown(button, content) {
        const isExpanded = button.classList.contains('expanded');
        
        if (isExpanded) {
            // Collapse
            button.classList.remove('expanded');
            content.classList.remove('expanded');
            button.innerHTML = '<span>View Analysis Details</span><span class="fixed-dropdown-arrow">▼</span>';
        } else {
            // Expand
            button.classList.add('expanded');
            content.classList.add('expanded');
            button.innerHTML = '<span>Hide Analysis Details</span><span class="fixed-dropdown-arrow">▼</span>';
        }
    }

    showFixedAlert(analysisResult, emailElement = null) {
        // Remove existing alerts
        document.querySelectorAll('.fixed-phishing-alert').forEach(el => el.remove());
        
        // Calculate percentages
        const isPhishing = analysisResult.prediction === 'Phishing Email';
        let phishingPercentage;
        
        console.log('🔍 PhishMail Guard Analysis Result:', {
            prediction: analysisResult.prediction,
            confidence: analysisResult.confidence,
            phishing_confidence: analysisResult.phishing_confidence,
            safe_confidence: analysisResult.safe_confidence
        });
        
        if (isPhishing) {
            phishingPercentage = (analysisResult.phishing_confidence || analysisResult.confidence || 0) * 100;
            console.log('📊 Phishing email detected, using phishing_confidence:', phishingPercentage + '%');
        } else {
            // For safe emails, use the phishing_confidence directly (already the phishing risk %)
            phishingPercentage = (analysisResult.phishing_confidence || analysisResult.confidence || 0) * 100;
            console.log('📊 Safe email detected, phishing risk:', phishingPercentage + '%');
        }
        
        const safePercentage = 100 - phishingPercentage;
        const alertType = this.getAlertType(phishingPercentage);
        const reasons = this.generateReasons(analysisResult, phishingPercentage);
        const riskText = this.getRiskAssessmentText(phishingPercentage);
        
        // Create alert element
        const alertElement = document.createElement('div');
        alertElement.className = `fixed-phishing-alert ${alertType.class}`;
        
        alertElement.innerHTML = `
            <div class="fixed-alert-header" style="background: ${alertType.bgColor}; color: ${alertType.color};">
                <div class="fixed-alert-icon">${alertType.icon}</div>
                <div class="fixed-alert-content">
                    <div class="fixed-alert-title">${alertType.title}</div>
                    <div class="fixed-alert-subtitle" style="color: ${alertType.color};">${alertType.subtitle}</div>
                    <div class="fixed-alert-percentage" style="background: ${alertType.color};">
                        ${phishingPercentage.toFixed(1)}% Phishing Risk
                    </div>
                </div>
                <button class="fixed-alert-close">×</button>
            </div>
            
            <button class="fixed-dropdown-toggle">
                <span>View Analysis Details</span>
                <span class="fixed-dropdown-arrow">▼</span>
            </button>
            
            <div class="fixed-dropdown-content">
                <div class="fixed-risk-assessment" style="color: ${alertType.color}; border-color: ${alertType.color};">
                    <div class="fixed-risk-header">
                        <div class="fixed-risk-indicator" style="background: ${alertType.color};"></div>
                        <h3 class="fixed-risk-title">Risk Assessment</h3>
                    </div>
                    <p class="fixed-risk-text">${riskText}</p>
                </div>
                
                <div class="fixed-risk-bars">
                    <div class="fixed-risk-bar">
                        <div class="fixed-risk-bar-label" style="color: #ef4444;">PHISHING RISK</div>
                        <div class="fixed-risk-bar-container">
                            <div class="fixed-risk-bar-fill phishing" style="width: ${phishingPercentage}%;"></div>
                        </div>
                        <div class="fixed-risk-percentage" style="color: #ef4444;">${phishingPercentage.toFixed(1)}%</div>
                    </div>
                    
                    <div class="fixed-risk-bar">
                        <div class="fixed-risk-bar-label" style="color: #10b981;">SAFETY SCORE</div>
                        <div class="fixed-risk-bar-container">
                            <div class="fixed-risk-bar-fill safe" style="width: ${safePercentage}%;"></div>
                        </div>
                        <div class="fixed-risk-percentage" style="color: #10b981;">${safePercentage.toFixed(1)}%</div>
                    </div>
                </div>
                
                <div class="fixed-analysis-details" style="color: ${alertType.color};">
                    <div class="fixed-analysis-header">
                        <span>🔍</span>
                        <h3 class="fixed-analysis-title">Analysis Details (${reasons.length} factors)</h3>
                    </div>
                    
                    <div class="fixed-reasons-list">
                        ${reasons.map((reason, index) => `
                            <div class="fixed-reason-item" style="animation-delay: ${index * 0.05}s;">
                                <div class="fixed-reason-bullet" style="background: ${alertType.color};"></div>
                                <p class="fixed-reason-text">${reason}</p>
                            </div>
                        `).join('')}
                    </div>
                </div>
            </div>
        `;
        
        // Add event listeners
        const closeBtn = alertElement.querySelector('.fixed-alert-close');
        const toggleBtn = alertElement.querySelector('.fixed-dropdown-toggle');
        const dropdownContent = alertElement.querySelector('.fixed-dropdown-content');
        
        closeBtn.addEventListener('click', () => {
            alertElement.remove();
        });
        
        toggleBtn.addEventListener('click', () => {
            this.toggleDropdown(toggleBtn, dropdownContent);
        });
        
        document.body.appendChild(alertElement);
        
        // Auto-close
        setTimeout(() => {
            if (alertElement.parentNode) {
                alertElement.remove();
            }
        }, alertType.autoCloseDelay);
        
        return alertElement;
    }

    // Test functions for the simplified system
    testUnsafe() {
        const testResult = {
            prediction: 'Phishing Email',
            confidence: 0.85,
            phishing_confidence: 0.85,
            safe_confidence: 0.15,
            reasons: ['This email uses urgent language to pressure you', 'The sender may not be who they claim to be', 'Links or requests in this email could be dangerous']
        };
        return this.showFixedAlert(testResult);
    }

    testSafe() {
        const testResult = {
            prediction: 'Safe Email',
            confidence: 0.92,
            phishing_confidence: 0.08,
            safe_confidence: 0.92,
            reasons: ['This email appears to be from a legitimate source', 'No suspicious patterns or dangerous links detected', 'The email format and language appear professional']
        };
        return this.showFixedAlert(testResult);
    }
}

// Initialize and export
window.FixedPhishingAlert = FixedPhishingAlert;
window.fixedPhishingAlert = new FixedPhishingAlert();

console.log('✅ Simplified Popup System (Safe/Unsafe) loaded successfully!');
console.log('📋 Test functions available:');
console.log('  - fixedPhishingAlert.testUnsafe() // Red popup for unsafe emails');
console.log('  - fixedPhishingAlert.testSafe()   // Green popup for safe emails');
