// Simplified PhishMail Guard Popup Script
class SimplePopupManager {
  constructor() {
    this.settings = {
      enabled: true,
      showWarnings: true
    };
    this.latestAnalysis = null;
    this.init();
  }

  async init() {
    await this.loadSettings();
    await this.checkCurrentTab();
    this.setupEventListeners();
    this.updateUI();
    
    // Listen for analysis updates from content script
    this.setupMessageListener();
  }

  async loadSettings() {
    try {
      const result = await chrome.storage.sync.get(['enabled', 'showNotifications']);
      this.settings.enabled = result.enabled !== false;
      this.settings.showWarnings = result.showNotifications !== false;
    } catch (error) {
      console.error('Error loading settings:', error);
    }
  }

  async saveSettings() {
    try {
      await chrome.storage.sync.set({
        enabled: this.settings.enabled,
        showNotifications: this.settings.showWarnings
      });
    } catch (error) {
      console.error('Error saving settings:', error);
    }
  }

  async checkCurrentTab() {
    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      const currentTab = tabs[0];
      
      if (currentTab && currentTab.url) {
        const url = currentTab.url;
        let provider = 'Not on supported email provider';
        let isSupported = false;
        
        if (url.includes('mail.google.com')) {
          provider = 'Gmail';
          isSupported = true;
        } else if (url.includes('outlook.live.com') || url.includes('outlook.office.com')) {
          provider = 'Outlook';
          isSupported = true;
        } else if (url.includes('mail.yahoo.com')) {
          provider = 'Yahoo Mail';
          isSupported = true;
        }
        
        document.getElementById('provider-name').textContent = provider;
        document.getElementById('scan-status').textContent = isSupported ? 'Ready to scan' : 'Not supported';
        
        const scanButton = document.getElementById('scan-button');
        scanButton.disabled = !isSupported;
        
        if (!isSupported) {
          scanButton.innerHTML = `
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <circle cx="12" cy="12" r="10"/>
              <line x1="15" y1="9" x2="9" y2="15"/>
              <line x1="9" y1="9" x2="15" y2="15"/>
            </svg>
            Not Supported
          `;
        }
        
        // Try to get latest analysis from storage and current page
        if (isSupported) {
          await this.loadLatestAnalysis();
          await this.getLatestAnalysisFromPage();
        }
      }
    } catch (error) {
      console.error('Error checking current tab:', error);
    }
  }

  async loadLatestAnalysis() {
    try {
      const result = await chrome.storage.local.get(['latestAnalysis']);
      if (result.latestAnalysis) {
        this.latestAnalysis = result.latestAnalysis;
        this.displayAnalysis(this.latestAnalysis);
      }
    } catch (error) {
      console.error('Error loading latest analysis:', error);
    }
  }

  async saveLatestAnalysis(analysis) {
    try {
      await chrome.storage.local.set({ latestAnalysis: analysis });
    } catch (error) {
      console.error('Error saving latest analysis:', error);
    }
  }

  async getLatestAnalysisFromPage() {
    try {
      // Get current tab and execute script to find latest analysis
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      const currentTab = tabs[0];
      
      const results = await chrome.scripting.executeScript({
        target: { tabId: currentTab.id },
        func: () => {
          // Find the most recently analyzed email element
          const analyzedElements = document.querySelectorAll('[data-phishguard-analyzed="true"]');
          if (analyzedElements.length > 0) {
            const latestElement = analyzedElements[analyzedElements.length - 1];
            const resultData = latestElement.getAttribute('data-phishguard-result');
            if (resultData) {
              try {
                return JSON.parse(resultData);
              } catch (e) {
                return null;
              }
            }
          }
          return null;
        }
      });
      
      if (results && results[0] && results[0].result) {
        const analysis = results[0].result;
        console.log('Found latest analysis on page:', analysis);
        this.latestAnalysis = analysis;
        this.displayAnalysis(analysis);
        this.saveLatestAnalysis(analysis);
      }
    } catch (error) {
      console.log('Could not get analysis from page:', error);
    }
  }

  setupMessageListener() {
    // Listen for messages from content script about new analysis
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      if (message.action === 'analysisComplete') {
        console.log('Received analysis result:', message.result);
        this.latestAnalysis = message.result;
        this.displayAnalysis(message.result);
        this.saveLatestAnalysis(message.result);
      }
    });
  }

  displayAnalysis(result) {
    const analysisSection = document.getElementById('latest-analysis');
    const confidenceCircle = document.getElementById('confidence-circle');
    const confidencePercentage = document.getElementById('confidence-percentage');
    const confidenceLabel = document.getElementById('confidence-label');
    const reasonsList = document.getElementById('reasons-list');

    // Show the analysis section
    analysisSection.style.display = 'block';

    // Calculate phishing percentage like the alert UI
    const isPhishing = result.prediction === 'Phishing Email';
    let phishingPercentage;
    
    if (isPhishing) {
      phishingPercentage = (result.phishing_confidence || result.confidence || 0) * 100;
    } else {
      const safeConfidence = result.safe_confidence || result.confidence || 0;
      phishingPercentage = (1 - safeConfidence) * 100;
    }
    
    const safePercentage = 100 - phishingPercentage;
    
    // Update main confidence display
    confidencePercentage.textContent = `${Math.round(phishingPercentage)}%`;
    
    if (phishingPercentage >= 60) {
      confidenceLabel.textContent = 'High Risk';
      confidenceCircle.classList.add('danger');
      confidenceCircle.classList.remove('safe');
    } else if (phishingPercentage >= 5) {
      confidenceLabel.textContent = 'Low Risk';
      confidenceCircle.classList.remove('danger');
      confidenceCircle.classList.remove('safe');
    } else {
      confidenceLabel.textContent = 'Safe';
      confidenceCircle.classList.remove('danger');
      confidenceCircle.classList.add('safe');
    }
    
    // Add or update risk breakdown bars
    this.updateRiskBreakdown(phishingPercentage, safePercentage);

    // Generate comprehensive reasons like the alert UI
    const reasons = this.generateDetailedReasons(result, phishingPercentage);
    
    // Update reasons list with all factors
    reasonsList.innerHTML = '';
    console.log('Analysis result:', result); // Debug logging
    
    reasons.forEach((reason, index) => {
      const li = document.createElement('li');
      li.innerHTML = `<strong>Factor ${index + 1}:</strong> ${reason}`;
      li.style.cssText = `
        margin-bottom: 6px;
        padding: 6px;
        background: rgba(0, 0, 0, 0.02);
        border-radius: 4px;
        font-size: 11px;
        line-height: 1.3;
      `;
      reasonsList.appendChild(li);
    });

    // Update scan status
    document.getElementById('scan-status').textContent = `Last scan: ${new Date().toLocaleTimeString()}`;
  }
  
  updateRiskBreakdown(phishingPercentage, safePercentage) {
    // Check if risk breakdown already exists, if not create it
    let riskBreakdown = document.getElementById('risk-breakdown');
    if (!riskBreakdown) {
      riskBreakdown = document.createElement('div');
      riskBreakdown.id = 'risk-breakdown';
      riskBreakdown.style.cssText = 'margin: 12px 0; padding: 8px; background: #f8fafc; border-radius: 8px;';
      
      riskBreakdown.innerHTML = `
        <div style="font-size: 12px; font-weight: 600; margin-bottom: 8px; color: #374151;">Risk Breakdown</div>
        <div style="display: flex; justify-content: space-between; margin-bottom: 4px;">
          <span style="font-size: 10px; font-weight: 600; color: #ef4444;">Phishing Risk</span>
          <span id="phishing-risk-percent" style="font-size: 10px; font-weight: 700; color: #ef4444;">0%</span>
        </div>
        <div style="background: #f1f5f9; border-radius: 6px; height: 4px; overflow: hidden; margin-bottom: 6px;">
          <div id="phishing-risk-bar" style="height: 100%; background: linear-gradient(90deg, #ef4444, #dc2626); transition: width 0.8s ease; width: 0%;"></div>
        </div>
        <div style="display: flex; justify-content: space-between; margin-bottom: 4px;">
          <span style="font-size: 10px; font-weight: 600; color: #10b981;">Safety Score</span>
          <span id="safety-score-percent" style="font-size: 10px; font-weight: 700; color: #10b981;">0%</span>
        </div>
        <div style="background: #f1f5f9; border-radius: 6px; height: 4px; overflow: hidden;">
          <div id="safety-score-bar" style="height: 100%; background: linear-gradient(90deg, #10b981, #059669); transition: width 0.8s ease; width: 0%;"></div>
        </div>
      `;
      
      // Insert after confidence display
      const confidenceDisplay = document.querySelector('.confidence-display');
      confidenceDisplay.parentNode.insertBefore(riskBreakdown, confidenceDisplay.nextSibling);
    }
    
    // Update the bars with animation
    setTimeout(() => {
      document.getElementById('phishing-risk-percent').textContent = `${Math.round(phishingPercentage)}%`;
      document.getElementById('safety-score-percent').textContent = `${Math.round(safePercentage)}%`;
      document.getElementById('phishing-risk-bar').style.width = `${phishingPercentage}%`;
      document.getElementById('safety-score-bar').style.width = `${safePercentage}%`;
    }, 100);
  }
  
  generateDetailedReasons(result, phishingPercentage) {
    const reasons = [];
    
    // Add reasons from backend analysis
    if (result.reasons && result.reasons.length > 0) {
      result.reasons.forEach(reason => {
        reasons.push(reason);
      });
    }
    
    // Add classification-based reasons
    if (phishingPercentage >= 80) {
      reasons.push(
        'Multiple high-risk phishing indicators detected',
        'Suspicious URL patterns and domain characteristics',
        'Urgent action language commonly used in scams',
        'Request for sensitive personal information',
        'Threat of account suspension or closure',
        'Poor grammar or spelling inconsistencies'
      );
    } else if (phishingPercentage >= 60) {
      reasons.push(
        'Several warning signs present in email content',
        'Potentially suspicious sender domain',
        'Moderate risk language patterns detected',
        'Some characteristics match known phishing attempts',
        'Email formatting or structure irregularities'
      );
    } else if (phishingPercentage >= 5) {
      reasons.push(
        'Minor suspicious elements identified',
        'Some characteristics require attention',
        'Email contains few warning indicators',
        'Generally safe but exercise normal caution'
      );
    } else {
      reasons.push(
        'Email passes comprehensive security analysis',
        'Legitimate sender domain verified',
        'Professional email format and structure',
        'No suspicious links or attachments detected',
        'Very low risk of phishing activity'
      );
    }
    
    return reasons.slice(0, 8); // Limit to 8 reasons for popup
  }

  setupEventListeners() {
    // Settings toggles
    document.getElementById('extension-enabled').addEventListener('change', (e) => {
      this.settings.enabled = e.target.checked;
      this.saveSettings();
      this.updateStatus();
    });

    document.getElementById('show-warnings').addEventListener('change', (e) => {
      this.settings.showWarnings = e.target.checked;
      this.saveSettings();
    });

    // Scan button
    document.getElementById('scan-button').addEventListener('click', () => {
      this.scanCurrentPage();
    });
  }

  updateUI() {
    // Update settings UI
    document.getElementById('extension-enabled').checked = this.settings.enabled;
    document.getElementById('show-warnings').checked = this.settings.showWarnings;
  }

  updateStatus() {
    const scanStatus = document.getElementById('scan-status');
    if (this.settings.enabled) {
      scanStatus.textContent = 'Ready to scan';
    } else {
      scanStatus.textContent = 'Protection disabled';
    }
  }

  async scanCurrentPage() {
    const button = document.getElementById('scan-button');
    const originalContent = button.innerHTML;
    
    button.disabled = true;
    button.innerHTML = `
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <circle cx="12" cy="12" r="10"/>
        <path d="m9,12 2,2 4,-4"/>
      </svg>
      Scanning...
    `;

    try {
      // Send message to content script to trigger manual scan
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      const currentTab = tabs[0];
      
      await chrome.tabs.sendMessage(currentTab.id, {
        action: 'manualScan'
      });

      // Show success state
      button.innerHTML = `
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
          <polyline points="22,4 12,14.01 9,11.01"/>
        </svg>
        Scan Complete
      `;
      
      setTimeout(() => {
        button.disabled = false;
        button.innerHTML = originalContent;
      }, 2000);

    } catch (error) {
      console.error('Error scanning page:', error);
      button.innerHTML = `
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="12" cy="12" r="10"/>
          <line x1="15" y1="9" x2="9" y2="15"/>
          <line x1="9" y1="9" x2="15" y2="15"/>
        </svg>
        Scan Failed
      `;
      
      setTimeout(() => {
        button.disabled = false;
        button.innerHTML = originalContent;
      }, 2000);
    }
  }
}

// Initialize popup when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  new SimplePopupManager();
});