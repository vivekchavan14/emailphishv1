# 🚀 Render Deployment Guide

## 📁 What to Deploy

**Deploy the `production-system/` folder** - this contains the complete FastAPI backend with advanced ML models.

## 🔧 Pre-Deployment Setup

### 1. Repository Structure
Your GitHub repository should have this structure:
```
emailphishv1/
├── production-system/          ← Deploy this folder
│   ├── main.py                 ← Entry point for Render
│   ├── requirements.txt        ← Dependencies
│   ├── render.yaml            ← Render configuration
│   ├── Dockerfile             ← Container option
│   ├── api/
│   │   └── production_api.py  ← FastAPI application
│   ├── models/
│   │   └── production_ml_models.py
│   ├── data/
│   │   └── dataset_manager.py
│   └── ...
```

### 2. Key Files for Deployment
- ✅ `main.py` - Entry point (automatically detects PORT from Render)
- ✅ `requirements.txt` - Streamlined dependencies for cloud deployment  
- ✅ `render.yaml` - Render service configuration
- ✅ `Dockerfile` - Alternative container deployment

## 🌐 Render Deployment Steps

### Option 1: GitHub Integration (Recommended)

1. **Connect GitHub Repository**
   - Go to [Render Dashboard](https://dashboard.render.com)
   - Click "New +" → "Web Service"
   - Connect your GitHub account
   - Select repository: `vivekchavan14/emailphishv1`

2. **Configure Service**
   ```
   Name: phishing-detection-api
   Runtime: Python 3
   Build Command: pip install -r requirements.txt
   Start Command: python main.py
   ```

3. **Set Environment Variables**
   ```
   PORT=8000                    (Render sets this automatically)
   PYTHON_VERSION=3.9.16
   API_ENV=production
   ENABLE_CORS=true
   LOG_LEVEL=info
   ```

4. **Advanced Settings**
   ```
   Health Check Path: /api/v2/health
   Root Directory: production-system
   Plan: Free (or Starter)
   Region: Ohio (US-East)
   ```

### Option 2: Manual Upload

1. **Prepare Deployment Package**
   - Download only the `production-system/` folder
   - Ensure all files are present (main.py, requirements.txt, etc.)

2. **Upload to Render**
   - Choose "Upload from computer" option
   - Upload the `production-system` folder as a ZIP file

## 🔍 Deployment Configuration Details

### Environment Variables
```bash
# Required
PORT=8000                    # Automatically set by Render
PYTHON_VERSION=3.9.16

# Optional
API_ENV=production
ENABLE_CORS=true
LOG_LEVEL=info
MODEL_CACHE_SIZE=1000
```

### Build Settings
```yaml
Runtime: Python 3.9
Build Command: pip install -r requirements.txt
Start Command: python main.py
Health Check: /api/v2/health
```

### Resource Requirements
```
Memory: 512MB (minimum for ML models)
CPU: 0.1 vCPU (Free tier)
Disk: 1GB (for model storage)
```

## 📊 Post-Deployment Verification

### 1. Check Deployment Status
- Monitor build logs in Render dashboard
- Verify service is "Live" status
- Check for any error messages

### 2. Test API Endpoints
Once deployed, your API will be available at:
`https://your-service-name.onrender.com`

Test these endpoints:
```bash
# Health check
GET https://your-service-name.onrender.com/api/v2/health

# Email analysis
POST https://your-service-name.onrender.com/api/v2/analyze/email
Content-Type: application/json
{
  "email": "Test email content",
  "sender": "test@example.com"
}

# API documentation
GET https://your-service-name.onrender.com/api/docs
```

### 3. Performance Monitoring
Monitor these metrics in Render dashboard:
- Response times
- Memory usage
- Error rates
- Request volume

## 🚨 Common Issues & Solutions

### 1. Build Failures
**Issue**: Dependency installation fails
**Solution**: 
- Check requirements.txt for conflicting versions
- Ensure Python 3.9 compatibility
- Remove optional dependencies if needed

### 2. Memory Issues
**Issue**: Service crashes due to memory limits
**Solution**:
- Upgrade to Starter plan ($7/month) for more memory
- Optimize model loading in production_ml_models.py
- Implement lazy loading of models

### 3. Cold Start Delays
**Issue**: First request after inactivity is slow
**Solution**:
- Use Render's persistent storage
- Implement model caching
- Consider paid plan for no cold starts

### 4. CORS Issues
**Issue**: Browser extension can't access API
**Solution**:
- Ensure ENABLE_CORS=true in environment
- Update browser extension manifest with new URL
- Check production_api.py CORS settings

## 🔧 Production Optimizations

### 1. Update Browser Extension
After deployment, update browser extension manifest:
```json
{
  "host_permissions": [
    "https://your-service-name.onrender.com/*"
  ]
}
```

### 2. Environment-Specific Settings
```python
# In production_api.py
import os

if os.getenv("API_ENV") == "production":
    # Production-specific configurations
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["https://yourdomain.com"],  # Restrict origins
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )
```

### 3. Performance Monitoring
Add monitoring endpoints:
```python
@app.get("/metrics")
async def get_metrics():
    return {
        "requests_processed": request_count,
        "models_loaded": len(ml_models.models),
        "cache_size": len(prediction_cache),
        "uptime": time.time() - start_time
    }
```

## 💰 Cost Estimation

### Free Tier
- ✅ 750 hours/month
- ✅ 512MB RAM
- ✅ 0.1 vCPU
- ❌ Sleeps after 15 minutes of inactivity

### Starter Plan ($7/month)
- ✅ Always on (no sleep)
- ✅ 512MB RAM
- ✅ 0.5 vCPU
- ✅ Better for production use

### Pro Plan ($25/month)  
- ✅ 2GB RAM
- ✅ 1 vCPU
- ✅ Best performance for ML models

## 🎯 Success Checklist

- [ ] Repository connected to Render
- [ ] Build completes successfully
- [ ] Service shows "Live" status
- [ ] Health check endpoint responds
- [ ] API documentation accessible
- [ ] Email analysis endpoint works
- [ ] Browser extension updated with new URL
- [ ] Performance monitoring set up

## 🔗 Useful Links

- [Render Documentation](https://render.com/docs)
- [Your Service Dashboard](https://dashboard.render.com)
- [GitHub Repository](https://github.com/vivekchavan14/emailphishv1)
- [API Documentation](https://your-service-name.onrender.com/api/docs)

---

🚀 **Ready to deploy!** Your production phishing detection system will be live and protecting users worldwide.