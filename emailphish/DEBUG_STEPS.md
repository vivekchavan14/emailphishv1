# 🔧 PhishMail Guard Debugging Guide

## Current Status
✅ Backend server is running on port 8000  
❌ Extension popup alerts are not showing

## Step-by-Step Debugging

### 1️⃣ **Check Extension Installation**

1. Open Chrome/Edge browser
2. Go to `chrome://extensions/` (or `edge://extensions/`)
3. Verify "PhishMail Guard" is listed and **enabled**
4. If not installed:
   - Enable "Developer mode" (toggle in top right)
   - Click "Load unpacked"
   - Select: `C:\Users\DELL\emailphish\Phishing-Email-Detection-System\frontend\browser-extension`

### 2️⃣ **Test Extension Loading**

1. Open the test page: Copy this path into browser address bar:
   ```
   file:///C:/Users/DELL/emailphish/Phishing-Email-Detection-System/frontend/browser-extension/test-email.html
   ```
2. Open browser console (F12)
3. Look for this message:
   ```
   PhishMail Guard test page loaded
   ```
4. After 2 seconds, should see:
   ```
   Checking for extension after page load...
   ```

### 3️⃣ **Run Debug Script**

1. **Copy and paste this entire script** into browser console:
   ```javascript
   // Quick Extension Test
   console.log('🔍 Testing PhishMail Guard...');
   
   // Check if extension is loaded
   setTimeout(() => {
       if (typeof PhishMailGuard !== 'undefined') {
           console.log('✅ Extension class found');
           if (window.phishGuard) {
               console.log('✅ Extension instance found');
               console.log('📧 Testing email scanning...');
               window.phishGuard.scanExistingEmails();
           }
       } else {
           console.log('❌ Extension not loaded');
       }
       
       // Test alert manually
       const testAlert = () => {
           const alertCard = document.createElement('div');
           alertCard.innerHTML = `
               <div style="position: fixed; top: 20px; right: 20px; background: white; 
                          border: 1px solid #dc2626; border-left: 6px solid #dc2626;
                          border-radius: 12px; padding: 16px; z-index: 999999; width: 350px;
                          font-family: system-ui; box-shadow: 0 10px 25px rgba(0,0,0,0.1);">
                   <div style="display: flex; align-items: center; gap: 12px;">
                       <div style="font-size: 24px;">⚠️</div>
                       <div style="flex: 1;">
                           <div style="font-weight: bold; color: #1f2937;">Phishing Email Detected</div>
                           <div style="font-size: 13px; color: #6b7280;">95.0% Phishing Risk</div>
                       </div>
                       <button onclick="this.parentElement.parentElement.parentElement.remove()" 
                               style="background: none; border: none; font-size: 18px; cursor: pointer;">×</button>
                   </div>
                   <div style="margin-top: 10px; font-size: 13px; color: #4b5563;">
                       Suspicious domain detected, urgent action language
                   </div>
               </div>
           `;
           document.body.appendChild(alertCard);
           console.log('✅ Manual test alert created');
       };
       
       window.testAlert = testAlert;
       console.log('📝 Run testAlert() to show a test popup');
       
   }, 1000);
   ```

### 4️⃣ **Check Extension Permissions**

1. In Chrome extensions page, click on "PhishMail Guard"
2. Go to "Details"
3. Verify these permissions are granted:
   - ✅ Access your data on mail.google.com
   - ✅ Access your data on outlook.live.com  
   - ✅ Access your data on outlook.office.com
   - ✅ Access your data on mail.yahoo.com

### 5️⃣ **Test on Real Email Provider**

1. Go to Gmail: https://mail.google.com
2. Open browser console (F12)
3. Look for these messages:
   ```
   PhishMail Guard starting initialization...
   Settings loaded. Enabled: true
   Starting email monitoring...
   ```
4. If you see errors, note them down

### 6️⃣ **Check Extension Settings**

1. Click the PhishMail Guard extension icon in browser toolbar
2. Verify these settings:
   - ✅ Protection Enabled: ON
   - ✅ Show Warnings: ON
3. If popup doesn't open, extension isn't properly loaded

### 7️⃣ **Manual Backend Test**

1. Open new browser tab
2. Go to: `http://127.0.0.1:8000/`
3. Should see: `{"status":"online","models_available":{...}}`
4. If error, restart backend:
   ```powershell
   cd C:\Users\DELL\emailphish\Phishing-Email-Detection-System\backend
   python main.py
   ```

### 8️⃣ **Common Issues & Fixes**

#### ❌ **Extension Not Loading**
```powershell
# Solution: Reload extension
# 1. Go to chrome://extensions/
# 2. Click reload button on PhishMail Guard
# 3. Refresh the email page
```

#### ❌ **No Email Elements Found**
```javascript
// Test in console on email page:
document.querySelectorAll('[data-message-id], [data-convid], .a3s').length
// Should return > 0
```

#### ❌ **Backend Connection Failed**
```powershell
# Restart backend server
cd C:\Users\DELL\emailphish\Phishing-Email-Detection-System\backend
python main.py
```

#### ❌ **CSS Not Loading**
```javascript
// Test CSS in console:
const test = document.createElement('div');
test.className = 'phishguard-alert-card';
document.body.appendChild(test);
console.log(getComputedStyle(test).borderRadius); // Should show "12px"
document.body.removeChild(test);
```

### 9️⃣ **Force Enable Debug Mode**

Add this to browser console on any email page:
```javascript
// Force enable extension
if (window.phishGuard) {
    window.phishGuard.isEnabled = true;
    window.phishGuard.showNotifications = true;
    window.phishGuard.realTimeAnalysis = true;
    console.log('✅ Extension force enabled');
    
    // Trigger scan
    window.phishGuard.scanExistingEmails();
} else {
    console.log('❌ Extension not found');
}
```

### 🔟 **Create Test Email Alert**

Run this in console to create a test alert:
```javascript
function createTestAlert() {
    // Remove existing alerts
    document.querySelectorAll('.phishguard-alert-card').forEach(el => el.remove());
    
    const alertHTML = `
        <div class="phishguard-alert-card high-danger" style="
            position: fixed; top: 20px; right: 20px; z-index: 999999;
            background: white; border-radius: 12px; overflow: hidden;
            box-shadow: 0 12px 28px rgba(220, 38, 38, 0.2);
            border-left: 6px solid #dc2626; width: 380px; max-width: calc(100vw - 40px);
            font-family: system-ui; animation: slideIn 0.4s ease;
        ">
            <div style="display: flex; align-items: center; padding: 16px; gap: 12px;
                       background: linear-gradient(135deg, #fef2f2, #fee2e2);">
                <div style="font-size: 24px;">⚠️</div>
                <div style="flex: 1;">
                    <div style="font-size: 16px; font-weight: 700; color: #1f2937; margin-bottom: 4px;">
                        Phishing – High Danger
                    </div>
                    <div style="font-size: 13px; font-weight: 600; color: #6b7280;">
                        95.0% Phishing Risk
                    </div>
                </div>
                <button onclick="this.closest('.phishguard-alert-card').remove()" style="
                    background: none; border: none; font-size: 18px; color: #9ca3af;
                    cursor: pointer; padding: 4px; border-radius: 4px; width: 24px; height: 24px;
                ">×</button>
            </div>
            <div style="padding: 12px 16px; font-size: 13px; color: #4b5563; 
                       border-top: 1px solid #f3f4f6;">
                Suspicious domain detected, urgent action required language
            </div>
        </div>
    `;
    
    document.body.insertAdjacentHTML('beforeend', alertHTML);
    
    // Auto-remove after 8 seconds
    setTimeout(() => {
        const alert = document.querySelector('.phishguard-alert-card');
        if (alert) alert.remove();
    }, 8000);
    
    console.log('✅ Test alert created');
}

// Add animation keyframes
if (!document.querySelector('#phishguard-animations')) {
    const style = document.createElement('style');
    style.id = 'phishguard-animations';
    style.textContent = `
        @keyframes slideIn {
            0% { opacity: 0; transform: translateX(100%); }
            100% { opacity: 1; transform: translateX(0); }
        }
    `;
    document.head.appendChild(style);
}

createTestAlert();
```

## Expected Results

After following these steps:

1. ✅ Extension should load without errors
2. ✅ Backend connection should work  
3. ✅ Email elements should be detected
4. ✅ Test alerts should appear
5. ✅ Real phishing detection should trigger alerts

## Next Steps

1. **Follow steps 1-3** first
2. **Report what you see** in console
3. **Try the manual test alert** (step 10)
4. **Test on Gmail/Outlook** with real emails

If the manual test alert works but real detection doesn't, the issue is likely with:
- Extension not detecting emails properly
- Backend analysis not triggering
- Settings being disabled

Let me know what messages you see in console! 🔍