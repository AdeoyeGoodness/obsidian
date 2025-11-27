# PowerShell script to set up Sentinel for network access

Write-Host "🌐 Setting up Sentinel for network access..." -ForegroundColor Cyan

# Get local IP address
$ipAddress = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" } | Select-Object -First 1).IPAddress

if (-not $ipAddress) {
    Write-Host "❌ Could not determine IP address" -ForegroundColor Red
    exit 1
}

Write-Host "📡 Your IP address: $ipAddress" -ForegroundColor Green

# Create .env.local file for console
$envContent = @"
VITE_QUERY_API=http://$ipAddress:8000
VITE_THREAT_MODEL_API=http://$ipAddress:8001/predict
"@

$envPath = "apps\console\.env.local"
$envContent | Out-File -FilePath $envPath -Encoding utf8
Write-Host "✅ Created $envPath" -ForegroundColor Green

# Configure Windows Firewall rules
Write-Host "🔥 Configuring Windows Firewall..." -ForegroundColor Yellow

$ports = @(3000, 8000, 8001)
foreach ($port in $ports) {
    $ruleName = "Sentinel-Port-$port"
    $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    
    if (-not $existingRule) {
        New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -LocalPort $port -Protocol TCP -Action Allow | Out-Null
        Write-Host "  ✅ Allowed port $port" -ForegroundColor Green
    } else {
        Write-Host "  ℹ️  Port $port already allowed" -ForegroundColor Gray
    }
}

Write-Host ""
Write-Host "✅ Setup complete!" -ForegroundColor Green
Write-Host ""
Write-Host "🚀 Access Sentinel from network devices:" -ForegroundColor Cyan
Write-Host "   Frontend:    http://$ipAddress:3000" -ForegroundColor White
Write-Host "   Query API:   http://$ipAddress:8000" -ForegroundColor White
Write-Host "   Threat API:  http://$ipAddress:8001" -ForegroundColor White
Write-Host ""
Write-Host "💡 Start services with: npm run dev" -ForegroundColor Yellow

