# Cloudflare Setup Guide

Now that the code is refactored for Cloudflare, follow these steps to deploy your website.

### 1. Initialize the Database (D1)
Run these commands in your terminal (inside the `eventlogger` folder) to create and initialize your database:

```bash
# Login to Cloudflare
npx wrangler login

# Create the database
npx wrangler d1 create eventlogger-db

# Initialize the schema
# Replace 'YOUR_DB_ID' with the ID given in the previous step
npx wrangler d1 execute eventlogger-db --file=schema.sql --remote
```

### 2. Create the Storage (R2)
Create a bucket for profile pictures:

```bash
npx wrangler r2 bucket create eventlogger-uploads
```

### 3. Update `wrangler.toml`
Open `wrangler.toml` and replace `YOUR_D1_DATABASE_ID_HERE` with the actual database ID from step 1.

### 4. Deploy to Cloudflare Pages
You can now deploy your site:

```bash
npx wrangler pages deploy .
```

---

### Local Testing
To test the site locally before deploying:
```bash
npx wrangler dev
```
Note: You may need to run `npx wrangler d1 execute eventlogger-db --file=schema.sql --local` first to set up the local mock database.
