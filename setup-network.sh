#!/bin/bash

# Bash script to set up Sentinel for network access

echo "🌐 Setting up Sentinel for network access..."

# Get local IP address
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    IP=$(ifconfig | grep "inet " | grep -v 127.0.0.1 | awk '{print $2}' | head -n 1)
else
    # Linux
    IP=$(hostname -I | awk '{print $1}')
fi

if [ -z "$IP" ]; then
    echo "❌ Could not determine IP address"
    exit 1
fi

echo "📡 Your IP address: $IP"

# Create .env.local file for console
cat > apps/console/.env.local << EOF
VITE_QUERY_API=http://$IP:8000
VITE_THREAT_MODEL_API=http://$IP:8001/predict
EOF

echo "✅ Created apps/console/.env.local"

# Configure firewall (Linux)
if command -v ufw &> /dev/null; then
    echo "🔥 Configuring firewall..."
    sudo ufw allow 3000/tcp
    sudo ufw allow 8000/tcp
    sudo ufw allow 8001/tcp
    echo "✅ Firewall rules added"
fi

echo ""
echo "✅ Setup complete!"
echo ""
echo "🚀 Access Sentinel from network devices:"
echo "   Frontend:    http://$IP:3000"
echo "   Query API:   http://$IP:8000"
echo "   Threat API:  http://$IP:8001"
echo ""
echo "💡 Start services with: npm run dev"

