# Environment Setup Guide

## Required Environment Variables

The `collector` and `query` services require environment variables to connect to PostgreSQL and Tinybird.

### Step 1: Create Root `.env` File

Create a `.env` file in the project root with the following content:

```env
# PostgreSQL Database Connection
# Format: postgresql://username:password@host:port/database
DATABASE_URL=postgresql://user:password@localhost:5432/pathwatch

# Tinybird Configuration
TB_URL=https://api.tinybird.co/v0/events
TB_TOKEN=your_tinybird_token_here
```

### Step 2: Create App-Specific `.env` Files

#### For `apps/collector/.env`:

```env
# PostgreSQL Database Connection
DATABASE_URL=postgresql://user:password@localhost:5432/pathwatch

# Tinybird Configuration
TB_URL=https://api.tinybird.co/v0/events
TB_TOKEN=your_tinybird_token_here
```

#### For `apps/query/.env`:

```env
# PostgreSQL Database Connection
DATABASE_URL=postgresql://user:password@localhost:5432/pathwatch

# Tinybird Token
TB_TOKEN=your_tinybird_token_here
```

### Step 3: Update Values

Replace the placeholder values with your actual credentials:

1. **DATABASE_URL**: Your PostgreSQL connection string
   - If you don't have PostgreSQL set up yet, you can:
     - Install PostgreSQL locally
     - Use a cloud provider (AWS RDS, Supabase, Neon, etc.)
     - Use Docker: `docker run -d -p 5432:5432 -e POSTGRES_PASSWORD=password postgres`

2. **TB_URL**: Tinybird API endpoint (usually `https://api.tinybird.co/v0/events`)

3. **TB_TOKEN**: Your Tinybird authentication token
   - Get this from your Tinybird dashboard: https://www.tinybird.co/

### Step 4: Run the Application

After setting up the environment variables, run:

```bash
npm run dev
```

All three services should now start without database connection errors.

## Troubleshooting

### Issue: "Missing environment variables"
- Ensure all `.env` files are created in the correct locations
- Check that variables are not commented out
- Restart the dev server after creating `.env` files

### Issue: PostgreSQL connection error
- Verify PostgreSQL is running
- Check connection string format
- Ensure database exists
- Verify username/password are correct

### Issue: Tinybird errors
- Verify TB_TOKEN is valid
- Check TB_URL is correct
- Ensure you have Tinybird account set up

