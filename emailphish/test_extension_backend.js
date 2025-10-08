// Test script to verify browser extension backend connectivity
// Copy and paste this into your browser's developer console on Gmail

console.log('🧪 Testing PhishMail Guard backend connectivity...');

const API_URL = 'http://localhost:8005/predict';

// Test function
async function testBackendConnection() {
    const testEmails = [
        {
            name: "Safe Google Email",
            content: "Hello, this is a notification from Google Drive. Your files have been shared successfully. Access them from your account dashboard."
        },
        {
            name: "Phishing Email", 
            content: "URGENT: Your account has been suspended due to suspicious activity! Click here immediately to verify your password or lose access forever!"
        }
    ];
    
    console.log('🔍 Testing backend connection to:', API_URL);
    
    for (const email of testEmails) {
        try {
            console.log(`\n📧 Testing: ${email.name}`);
            console.log('Email content:', email.content);
            
            const response = await fetch(API_URL, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ email: email.content }),
            });
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const result = await response.json();
            
            console.log('✅ Result:', {
                prediction: result.prediction,
                confidence: `${(result.confidence * 100).toFixed(1)}%`,
                phishing_confidence: `${(result.phishing_confidence * 100).toFixed(1)}%`,
                reasons: result.reasons,
                analysis_time: `${result.analysis_time}ms`
            });
            
        } catch (error) {
            console.error(`❌ Error testing ${email.name}:`, error.message);
        }
    }
    
    // Test health endpoint
    try {
        console.log('\n🏥 Testing health endpoint...');
        const healthResponse = await fetch('http://localhost:8005/health');
        const healthData = await healthResponse.json();
        
        console.log('✅ Backend Health:', {
            status: healthData.status,
            models: healthData.models,
            performance: healthData.performance
        });
        
    } catch (error) {
        console.error('❌ Health check failed:', error.message);
    }
}

// Run the test
testBackendConnection().then(() => {
    console.log('\n🎉 Backend connectivity test completed!');
    console.log('📝 If you see successful results above, your extension should work properly.');
    console.log('🔧 If there are errors, check that the backend is running on localhost:8005');
});

// Also test the chrome extension messaging (if available)
if (typeof chrome !== 'undefined' && chrome.runtime) {
    console.log('\n🔌 Testing Chrome extension messaging...');
    
    const testEmail = "Hello, this is a test email from Google. Your account is secure.";
    
    chrome.runtime.sendMessage(
        { 
            action: 'analyzeEmail', 
            emailContent: testEmail 
        },
        (response) => {
            if (chrome.runtime.lastError) {
                console.error('❌ Extension messaging error:', chrome.runtime.lastError.message);
            } else {
                console.log('✅ Extension response:', response);
            }
        }
    );
} else {
    console.log('ℹ️ Chrome extension API not available (normal if not running in extension context)');
}