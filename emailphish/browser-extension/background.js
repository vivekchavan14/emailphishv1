// Background service worker for PhishMail Guard
const API_URL = 'http://localhost:8000/predict';
const API_SENDER_CHECK_URL = 'http://localhost:8000/check_sender';

// Cache for recent predictions to avoid duplicate API calls
const predictionCache = new Map();
const CACHE_DURATION = 5 * 60 * 1000; // 5 minutes

// Listen for messages from content scripts
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'analyzeEmail') {
    handleEmailAnalysis(request.emailContent, sendResponse);
    return true; // Keep message channel open for async response
  }
  
  if (request.action === 'checkSender') {
    handleSenderCheck(request.emailContent, sendResponse);
    return true; // Keep message channel open for async response
  }
  
  if (request.action === 'updateBadge') {
    updateExtensionBadge(request.phishingCount, sender.tab.id);
  }
  
  if (request.action === 'showNotification') {
    showPhishingNotification(request.title, request.message, request.confidence);
  }
});

// Handle email analysis with caching
async function handleEmailAnalysis(emailContent, sendResponse) {
  console.log('Background: Starting enhanced email analysis...');
  
  try {
    const contentHash = hashString(emailContent);
    
    // Check cache first
    const cached = predictionCache.get(contentHash);
    if (cached && Date.now() - cached.timestamp < CACHE_DURATION) {
      console.log('Background: Using cached result');
      sendResponse(cached.result);
      return;
    }
    
    console.log('Background: Making API call to enhanced backend:', API_URL);
    
    // Make API call
    const response = await fetch(API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ email: emailContent }),
    });
    
    console.log('Background: API response status:', response.status);
    
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }
    
    const result = await response.json();
    console.log('Background: Enhanced analysis complete:', {
      prediction: result.prediction,
      confidence: result.confidence,
      isLegitimate: result.is_legitimate_sender,
      reasons: result.reasons
    });
    
    // Cache the result
    predictionCache.set(contentHash, {
      result: result,
      timestamp: Date.now()
    });
    
    // Clean old cache entries
    cleanCache();
    
    sendResponse(result);
    
  } catch (error) {
    console.error('Background: Error analyzing email:', error);
    
    let errorMessage = 'Failed to analyze email';
    if (error.message.includes('Failed to fetch')) {
      errorMessage = 'Cannot connect to backend server. Please check your internet connection.';
    } else if (error.message.includes('HTTP 5')) {
      errorMessage = 'Backend server error. Please check server logs';
    } else if (error.message.includes('HTTP 4')) {
      errorMessage = 'Bad request to backend server';
    }
    
    const errorResult = {
      error: true,
      message: errorMessage,
      prediction: 'Unknown',
      confidence: 0,
      phishing_confidence: 0,
      safe_confidence: 0,
      reasons: ['Analysis failed due to technical error']
    };
    
    sendResponse(errorResult);
  }
}

// Handle sender legitimacy check
async function handleSenderCheck(emailContent, sendResponse) {
  console.log('Background: Checking sender legitimacy...');
  
  try {
    const response = await fetch(API_SENDER_CHECK_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ email: emailContent }),
    });
    
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }
    
    const result = await response.json();
    console.log('Background: Sender check complete:', {
      isLegitimate: result.is_legitimate,
      reason: result.reason,
      domains: result.extracted_domains
    });
    
    sendResponse(result);
    
  } catch (error) {
    console.error('Background: Error checking sender:', error);
    sendResponse({
      error: true,
      message: 'Failed to check sender legitimacy',
      is_legitimate: false,
      reason: 'Check failed'
    });
  }
}

// Update extension badge with phishing count
function updateExtensionBadge(count, tabId) {
  const badgeText = count > 0 ? count.toString() : '';
  const badgeColor = count > 0 ? '#ef4444' : '#10b981';
  
  chrome.action.setBadgeText({
    text: badgeText,
    tabId: tabId
  });
  
  chrome.action.setBadgeBackgroundColor({
    color: badgeColor,
    tabId: tabId
  });
}

// Simple string hashing function
function hashString(str) {
  let hash = 0;
  if (str.length === 0) return hash;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash; // Convert to 32bit integer
  }
  return hash;
}

// Clean old cache entries
function cleanCache() {
  const now = Date.now();
  for (const [key, value] of predictionCache.entries()) {
    if (now - value.timestamp > CACHE_DURATION) {
      predictionCache.delete(key);
    }
  }
}

// Clean cache every 10 minutes
setInterval(cleanCache, 10 * 60 * 1000);

// Show phishing notification
function showPhishingNotification(title, message, confidence) {
  try {
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNDgiIGhlaWdodD0iNDgiIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHBhdGggZD0iTTEyIDlWMTNNMTIgMTdIMTIuMDFNNS42IDE5SDEuOUw2IDEyTDEwLjIgNUgxMy44TDE4IDEySDE0LjRMMTIgMTdIMTJaIiBzdHJva2U9IiNlZjQ0NDQiIHN0cm9rZS13aWR0aD0iMiIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIi8+Cjwvc3ZnPgo=',
      title: title,
      message: message,
      priority: 2
    });
  } catch (error) {
    console.error('Failed to show notification:', error);
  }
}

// Initialize extension
chrome.runtime.onInstalled.addListener(() => {
  console.log('PhishMail Guard extension installed');
  
  // Set default settings
  chrome.storage.sync.set({
    enabled: true,
    realTimeAnalysis: true,
    showNotifications: true,
    confidenceThreshold: 0.7
  });
});

// Handle tab updates to reset badge
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    const isEmailProvider = tab.url.includes('mail.google.com') ||
                           tab.url.includes('outlook.live.com') ||
                           tab.url.includes('outlook.office.com') ||
                           tab.url.includes('mail.yahoo.com');
    
    if (isEmailProvider) {
      chrome.action.setBadgeText({ text: '', tabId: tabId });
    }
  }
});