#!/bin/bash
# Git Helper Script for Production Phishing Detection System

set -e

echo "🚀 Production Phishing Detection System - Git Helper"
echo "═══════════════════════════════════════════════════════"

# Function to show status
show_status() {
    echo ""
    echo "📊 Current Status:"
    echo "─────────────────"
    git status --short
    echo ""
    echo "📝 Recent Commits:"
    echo "─────────────────"
    git log --oneline -5
    echo ""
}

# Function to add and commit changes
quick_commit() {
    echo ""
    echo "📥 Adding all changes..."
    git add .
    
    echo ""
    echo "💬 Enter commit message (or press Enter for default):"
    read -r commit_msg
    
    if [ -z "$commit_msg" ]; then
        commit_msg="📝 Update production phishing detection system - $(date '+%Y-%m-%d %H:%M')"
    fi
    
    echo ""
    echo "✅ Committing with message: $commit_msg"
    git commit -m "$commit_msg"
    
    echo ""
    echo "🔄 Changes committed successfully!"
}

# Function to push to GitHub
push_changes() {
    echo ""
    echo "🌐 Pushing to GitHub..."
    
    if git remote get-url origin >/dev/null 2>&1; then
        git push
        echo "✅ Successfully pushed to GitHub!"
    else
        echo "❌ No remote repository configured."
        echo "🔗 Add remote with: git remote add origin https://github.com/YOUR_USERNAME/production-phishing-detection.git"
    fi
}

# Function to create a new branch
create_branch() {
    echo ""
    echo "🌿 Enter new branch name:"
    read -r branch_name
    
    if [ -n "$branch_name" ]; then
        git checkout -b "$branch_name"
        echo "✅ Created and switched to branch: $branch_name"
    else
        echo "❌ Branch name cannot be empty"
    fi
}

# Function to deploy updates
deploy_production() {
    echo ""
    echo "🚀 Production Deployment Checklist:"
    echo "──────────────────────────────────"
    echo "1. ✅ Run tests: cd production-system && python3 simple_test.py"
    echo "2. ✅ Check API health: curl http://localhost:8001/api/v2/health"
    echo "3. ✅ Verify browser extension works"
    echo "4. ✅ Update version numbers if needed"
    echo "5. ✅ Create Git tag: git tag -a v2.0.1 -m 'Production release'"
    echo "6. ✅ Push tags: git push --tags"
    echo ""
}

# Main menu
while true; do
    echo ""
    echo "🛠️  What would you like to do?"
    echo "────────────────────────────────"
    echo "1) Show status"
    echo "2) Quick commit (add all + commit)"
    echo "3) Push to GitHub"
    echo "4) Commit and push (combined)"
    echo "5) Create new branch"
    echo "6) Show deployment checklist"
    echo "7) Exit"
    echo ""
    
    read -p "Choose option (1-7): " choice
    
    case $choice in
        1)
            show_status
            ;;
        2)
            quick_commit
            ;;
        3)
            push_changes
            ;;
        4)
            quick_commit
            push_changes
            ;;
        5)
            create_branch
            ;;
        6)
            deploy_production
            ;;
        7)
            echo ""
            echo "👋 Happy coding! Your production system is awesome!"
            exit 0
            ;;
        *)
            echo "❌ Invalid option. Please choose 1-7."
            ;;
    esac
done