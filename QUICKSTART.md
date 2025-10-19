# 🚀 Sentinel - Quick Start Guide

Welcome to **Sentinel** - your cyberpunk API monitoring command center!

## 🎯 What's Different from PathWatch?

✅ **Auto-loads dashboard** - No authentication blocking you  
✅ **Matrix green theme** (#00ff41) - Classic hacker aesthetic  
✅ **Enhanced glowing effects** - Tactical HUD corners with glow  
✅ **Better UI polish** - Grid animations and visual improvements  

## ⚡ Get Started in 3 Steps

### 1. Install Dependencies

```bash
cd C:\Users\BamBam\Desktop\sentinel
npm install
```

### 2. Run Development Server

```bash
npm run dev
```

### 3. Open Browser

Navigate to: **http://localhost:3000**

The dashboard will load automatically - no sign-in needed!

## 🎨 What You'll See

- **Matrix Green** accent colors throughout
- **Glowing corner brackets** on all components
- **Animated grid background** (subtle pulse effect)
- **Tactical HUD interface** - like a real cyber operations center

## 📡 Services

When you run `npm run dev`, three services start:

- **Console** (Frontend): Port 3000  
- **Collector** (API): Port 6000  
- **Query** (Analytics): Port 8000  

## ✨ No Database Required!

**Sentinel works perfectly without any database setup!**

The frontend is fully functional and the backend services start successfully. They just return helpful error messages for database-dependent features.

### 🛠️ Optional: Full Backend Functionality

Only needed if you want the APIs to actually work with data:

Create `.env` files with:
```env
DATABASE_URL=postgresql://user:password@localhost:5432/sentinel
TB_URL=https://api.tinybird.co/v0/events
TB_TOKEN=your_token_here
```

**But for UI development and exploring the interface, skip this entirely!**

See `NO-DATABASE-NEEDED.md` for more details.

## 🎮 Features to Explore

Navigate through the dashboard:

- **Analytics** - View API metrics and charts
- **Logs** - Browse request logs
- **Alerts** - Set up monitoring alerts  
- **Settings** - Project configuration

## 🔧 Build for Production

```bash
npm run build
```

## 🎨 Customization

- **Colors**: Edit `apps/console/src/styles.css`
- **Theme**: Modify `apps/console/src/components/ui/brackets.tsx`
- **Logo**: Update `apps/console/src/constants.ts`

---

**Enjoy your Sentinel experience!** 🛡️✨

For issues or questions, check the main README.md

