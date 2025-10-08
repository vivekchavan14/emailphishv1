// PhishMail Guard Content Script - Clean Version
console.log('🛡️ PhishMail Guard starting...');

class PhishMailGuard {
  constructor() {
    this.processedEmails = new Set();
    this.phishingCount = 0;
    this.isEnabled = true;
    this.showNotifications = true;
    this.realTimeAnalysis = true;
    this.observer = null;
    this.emailProvider = this.detectEmailProvider();
    this.alertUI = null;
    
    this.init();
  }

  async init() {
    console.log('🚀 PhishMail Guard initializing...');
    
    // Wait for Alert UI to be available
    await this.waitForAlertUI();
    
    // Load settings
    await this.loadSettings();
    
    if (!this.isEnabled) {
      console.log('❌ Extension disabled, exiting');
      return;
    }
    
    // Start monitoring emails
    this.startEmailMonitoring();
    
    console.log('✅ PhishMail Guard initialized for', this.emailProvider);
  }
  
  async waitForAlertUI() {
    return new Promise((resolve) => {
      const checkForUI = () => {
        if (window.fixedPhishingAlert) {
          this.alertUI = window.fixedPhishingAlert;
          console.log('✅ Fixed Popup Alert UI system loaded');
          resolve();
        } else {
          setTimeout(checkForUI, 100);
        }
      };
      checkForUI();
    });
  }

  async loadSettings() {
    try {
      const settings = await chrome.storage.sync.get([
        'enabled',
        'realTimeAnalysis',
        'showNotifications',
        'confidenceThreshold'
      ]);
      
      this.isEnabled = settings.enabled !== false;
      this.realTimeAnalysis = settings.realTimeAnalysis !== false;
      this.showNotifications = settings.showNotifications !== false;
      this.confidenceThreshold = settings.confidenceThreshold || 0.7;
    } catch (error) {
      console.error('Error loading settings:', error);
    }
  }

  detectEmailProvider() {
    const hostname = window.location.hostname;
    if (hostname.includes('mail.google.com')) return 'gmail';
    if (hostname.includes('outlook.live.com') || hostname.includes('outlook.office.com')) return 'outlook';
    if (hostname.includes('mail.yahoo.com')) return 'yahoo';
    return 'unknown';
  }

  startEmailMonitoring() {
    console.log('📧 Starting email monitoring...');
    
    // Initial scan
    setTimeout(() => {
      this.scanExistingEmails();
    }, 1000);
    
    // Set up mutation observer
    this.observer = new MutationObserver((mutations) => {
      if (!this.realTimeAnalysis) return;
      
      let shouldProcess = false;
      mutations.forEach((mutation) => {
        mutation.addedNodes.forEach((node) => {
          if (node.nodeType === Node.ELEMENT_NODE) {
            if (this.containsEmailContent(node)) {
              shouldProcess = true;
            }
          }
        });
      });
      
      if (shouldProcess) {
        clearTimeout(this.processingTimeout);
        this.processingTimeout = setTimeout(() => {
          this.scanExistingEmails();
        }, 500);
      }
    });

    this.observer.observe(document.body, {
      childList: true,
      subtree: true
    });
  }

  containsEmailContent(node) {
    const emailSelectors = [
      '[data-message-id]', '.a3s', '[data-convid]', '[data-test-id*="message"]',
      '.message-content', '.rps_', '[data-automation-id*="message"]'
    ];
    
    return emailSelectors.some(selector => {
      return node.matches && node.matches(selector) || node.querySelector && node.querySelector(selector);
    });
  }

  scanExistingEmails() {
    console.log('🔍 Scanning existing emails...');
    const emails = this.findEmails();
    console.log(`Found ${emails.length} emails to process`);
    
    emails.forEach((email, index) => {
      setTimeout(() => {
        this.processEmail(email);
      }, index * 100);
    });
  }

  findEmails(container = document) {
    let emails = [];
    
    switch (this.emailProvider) {
      case 'gmail':
        emails = Array.from(container.querySelectorAll([
          '[data-message-id]',
          '.ii.gt .a3s.aiL',
          '.adn.ads .a3s.aiL',
          '.a3s[data-body]',
          '[data-thread-id] .a3s'
        ].join(',')));
        break;
        
      case 'outlook':
        emails = Array.from(container.querySelectorAll([
          '[data-convid]',
          '.rps_2bc8',
          '[data-automation-id="messageBody"]'
        ].join(',')));
        break;
        
      case 'yahoo':
        emails = Array.from(container.querySelectorAll([
          '[data-test-id="message-view-body"]',
          '.message-content'
        ].join(',')));
        break;
    }
    
    // Filter valid emails
    return emails.filter(email => {
      if (!email || !email.textContent) return false;
      const content = email.textContent.trim();
      return content.length > 50 && !email.getAttribute('data-phishguard-analyzed');
    });
  }

  async processEmail(emailElement) {
    if (!emailElement || !this.isEnabled) return;
    
    // Check if already analyzed
    if (emailElement.getAttribute('data-phishguard-analyzed') === 'true') return;
    
    const emailId = this.getEmailId(emailElement);
    if (!emailId || this.processedEmails.has(emailId)) return;
    
    this.processedEmails.add(emailId);
    
    const emailContent = this.extractEmailContent(emailElement);
    if (!emailContent || emailContent.length < 50) return;
    
    console.log('🔍 Processing email:', emailId.substring(0, 20) + '...');
    
    try {
      const result = await this.analyzeEmail(emailContent);
      
      if (result && !result.error) {
        console.log('✅ Analysis successful:', result.prediction);
        this.displayResult(emailElement, result);
      } else {
        console.error('❌ Analysis failed:', result?.message);
        this.showErrorNotification(result?.message || 'Analysis failed');
      }
    } catch (error) {
      console.error('🚨 Error processing email:', error);
      this.showErrorNotification('Failed to analyze email: ' + error.message);
    }
  }

  getEmailId(emailElement) {
    return emailElement.getAttribute('data-message-id') ||
           emailElement.getAttribute('data-convid') ||
           emailElement.getAttribute('data-test-id') ||
           emailElement.textContent.substring(0, 100).replace(/\s/g, '');
  }

  extractEmailContent(emailElement) {
    let content = emailElement.textContent || emailElement.innerText || '';
    content = content.replace(/\s+/g, ' ').trim();
    
    if (content.length > 2000) {
      content = content.substring(0, 2000);
    }
    
    return content;
  }

  async analyzeEmail(emailContent) {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage({
        action: 'analyzeEmail',
        emailContent: emailContent
      }, (response) => {
        resolve(response);
      });
    });
  }

  displayResult(emailElement, result) {
    // Store result invisibly
    emailElement.setAttribute('data-phishguard-result', JSON.stringify(result));
    emailElement.setAttribute('data-phishguard-analyzed', 'true');
    
    // Show alert using fixed popup system
    if (this.alertUI && this.showNotifications) {
      console.log('🎨 Showing fixed popup alert with working dropdown...');
      this.alertUI.showFixedAlert(result, emailElement);
    } else if (this.showNotifications) {
      console.log('🔔 Showing fallback notification...');
      this.showBasicNotification(result);
    }
    
    // Update badge for phishing emails
    if (result.prediction === 'Phishing Email') {
      this.phishingCount++;
      this.updateBadge();
    }
    
    console.log('🛡️ Analysis complete:', {
      prediction: result.prediction,
      confidence: result.confidence || result.phishing_confidence || 0
    });
  }

  showBasicNotification(result) {
    const isPhishing = result.prediction === 'Phishing Email';
    const confidence = result.phishing_confidence || result.confidence || 0;
    const phishingPercentage = isPhishing ? (confidence * 100) : ((1 - confidence) * 100);
    
    // Create notification
    const notification = document.createElement('div');
    notification.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      z-index: 9999999;
      background: ${isPhishing ? '#fef2f2' : '#f0fdf4'};
      border: 2px solid ${isPhishing ? '#dc2626' : '#059669'};
      border-radius: 12px;
      padding: 16px;
      max-width: 350px;
      font-family: system-ui;
      box-shadow: 0 10px 25px rgba(0,0,0,0.15);
    `;
    
    notification.innerHTML = `
      <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 8px;">
        <div style="font-size: 24px;">${isPhishing ? '⚠️' : '✅'}</div>
        <div>
          <div style="font-weight: bold; color: ${isPhishing ? '#dc2626' : '#059669'};">
            ${isPhishing ? 'Phishing Email Detected' : 'Email is Safe'}
          </div>
          <div style="font-size: 13px; color: #666;">
            ${phishingPercentage.toFixed(1)}% Phishing Risk
          </div>
        </div>
        <button onclick="this.parentElement.parentElement.remove()" 
                style="background: none; border: none; font-size: 18px; cursor: pointer; margin-left: auto;">
          ×
        </button>
      </div>
      <div style="font-size: 13px; color: #555;">
        ${result.reasons && result.reasons[0] ? result.reasons[0] : 'Analysis complete'}
      </div>
    `;
    
    document.body.appendChild(notification);
    
    // Auto-remove
    setTimeout(() => {
      if (notification.parentNode) notification.remove();
    }, isPhishing ? 8000 : 4000);
  }

  showErrorNotification(message) {
    console.log('🚨 Showing error notification:', message);
    const notification = document.createElement('div');
    notification.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      z-index: 9999999;
      background: #fef2f2;
      border: 2px solid #ef4444;
      border-radius: 12px;
      padding: 16px;
      max-width: 350px;
      font-family: system-ui;
      box-shadow: 0 10px 25px rgba(0,0,0,0.15);
    `;
    
    notification.innerHTML = `
      <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 8px;">
        <div style="font-size: 24px;">🚨</div>
        <div>
          <div style="font-weight: bold; color: #ef4444;">
            PhishMail Guard Error
          </div>
          <div style="font-size: 13px; color: #666;">
            Scan Failed
          </div>
        </div>
        <button onclick="this.parentElement.parentElement.remove()" 
                style="background: none; border: none; font-size: 18px; cursor: pointer; margin-left: auto;">
          ×
        </button>
      </div>
      <div style="font-size: 13px; color: #555;">
        ${message}
      </div>
    `;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
      if (notification.parentNode) notification.remove();
    }, 6000);
  }

  updateBadge() {
    chrome.runtime.sendMessage({
      action: 'updateBadge',
      phishingCount: this.phishingCount
    });
  }

  sendAnalysisToPopup(result) {
    try {
      chrome.runtime.sendMessage({
        action: 'analysisComplete',
        result: result
      });
    } catch (error) {
      console.log('Could not send analysis to popup:', error);
    }
  }

  destroy() {
    console.log('🧹 Cleaning up PhishMail Guard...');
    
    if (this.observer) {
      this.observer.disconnect();
    }
    
    if (this.processingTimeout) {
      clearTimeout(this.processingTimeout);
    }
    
    // Clean up UI elements
    document.querySelectorAll('.phishguard-alert-card, .phishing-alert-card, .complete-phishing-alert, .fixed-phishing-alert').forEach(el => {
      el.remove();
    });
  }
}

// Initialize extension
let phishGuard = null;

// Wait for page to load
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    setTimeout(() => {
      phishGuard = new PhishMailGuard();
    }, 2000);
  });
} else {
  setTimeout(() => {
    phishGuard = new PhishMailGuard();
  }, 2000);
}

// Listen for messages from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'manualScan' && phishGuard) {
    console.log('📧 Manual scan requested');
    phishGuard.scanExistingEmails();
    sendResponse({ success: true });
    return true;
  }
});

// Listen for settings changes
chrome.storage.onChanged.addListener((changes, namespace) => {
  if (namespace === 'sync' && phishGuard) {
    phishGuard.loadSettings();
  }
});

// Clean up on unload
window.addEventListener('beforeunload', () => {
  if (phishGuard) {
    phishGuard.destroy();
  }
});

console.log('✅ PhishMail Guard content script loaded successfully');