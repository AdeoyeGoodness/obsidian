# 🔧 Sentinel Troubleshooting

## Common Issues & Solutions

### ❌ "WebStandard does not support listen" Error

**What you see:**
```
Error: WebStandard does not support listen, you might want to export default Elysia.fetch instead
```

**What it means:**
The collector and query services use Elysia framework, which is optimized for Bun runtime. When running with Node.js, they can't start.

**Solution:**
✅ **This is already handled!** The services will show a friendly warning and skip starting. The frontend still works perfectly.

**If you want full backend functionality:**
Install and use Bun:
```bash
# Install Bun
# Windows: https://bun.sh/docs/installation

# Then run with Bun
bun run dev
```

---

### ⚠️ Database Connection Warnings

**What you see:**
```
⚠️  Missing environment variables. Some features will not work.
❌ Database connection failed
```

**What it means:**
No database is configured (which is fine!).

**Solution:**
✅ **Ignore this!** The frontend works great without a database. Only needed for actual API data processing.

---

### 🔌 Port Already in Use

**What you see:**
```
Port 3000 is in use, trying another one...
➜  Local:   http://localhost:3001/
```

**What it means:**
Something else is using port 3000.

**Solution:**
✅ **Vite automatically finds the next available port.** Just use the URL it shows (like 3001, 3002, etc.)

---

### 🛠️ Services Overview

| Service | Port | Status | Notes |
|---------|------|--------|-------|
| Console | 3000 | ✅ Always works | The frontend - this is what you need! |
| Collector | 6000 | ⚠️ Node.js: Skips start<br>✅ Bun: Works | Backend API (optional) |
| Query | 8000 | ⚠️ Node.js: Skips start<br>✅ Bun: Works | Backend API (optional) |

---

## 💡 Quick Fixes

### Just Want the Frontend?
```bash
npm run console:dev
```
This runs only the console (frontend) - perfect for UI development!

### Want Everything to Work?
Use Bun instead of Node.js:
```bash
bun install
bun run dev
```

---

## 🎯 Bottom Line

**For Frontend Development:**
- ✅ Node.js + npm works perfectly
- ✅ Console loads and runs great
- ✅ Backend warnings are normal - ignore them!

**For Full Stack Development:**
- 🚀 Use Bun runtime
- 🗄️ Set up PostgreSQL
- 🔑 Add Tinybird credentials

---

**Questions?** Check out:
- `QUICKSTART.md` - Quick setup
- `NO-DATABASE-NEEDED.md` - Why you don't need DB
- `README.md` - Full documentation

