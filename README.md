# Physiotherapy Homecare & Rehabilitation Clinic — Secure Portal

Production-oriented clinic website + admin portal with PostgreSQL-backed patient records and PDF receipts.

## Included
- Public clinic website (`/`)
- Admin portal (`/admin`)
- Secure server-side sessions (HTTP-only cookie)
- PostgreSQL database
- Password hashing with bcrypt
- Login rate limiting, Helmet security headers, validation with Zod
- Patient add/edit/delete (deletion is blocked when receipts exist)
- Receipt creation/history/deletion
- A4 PDF payment receipt generation
- Clinic logo, location photo and equipment image

## Setup
1. Install Node.js 20+.
2. Create a PostgreSQL database (Neon, Supabase Postgres, Railway, Render Postgres, or your own server).
3. Copy `.env.example` to `.env` and set `DATABASE_URL`, a random `SESSION_SECRET` (32+ chars), and the initial admin password.
4. Run `npm install`.
5. Run `npm run db:init`.
6. Run `npm start`.
7. Open `http://localhost:3000` and use the Admin button.

### Initial admin credentials
The requested username is `physio@vpd`. The initial password should be set through `ADMIN_PASSWORD` during setup rather than stored in source code. On first login, the portal forces a password change.

## Production checklist
- Use HTTPS.
- Use a managed PostgreSQL database with encrypted connections and automated backups.
- Set `NODE_ENV=production`.
- Use a long random `SESSION_SECRET` stored only in your hosting provider's environment variables.
- Rotate the initial admin password immediately.
- Restrict database access to the application.
- Configure regular backups and a retention policy appropriate for clinical records.
- Add additional staff accounts/roles before multiple people use the portal.
- Confirm your local privacy, retention and medical-record obligations before storing real patient data.

## Deployment
This app is a Node/Express server and is best deployed to a service that supports a persistent Node process and PostgreSQL, such as Render, Railway, Fly.io, or a VPS. Vercel can host suitable architectures, but this specific Express + session + PostgreSQL app is intentionally kept simple for a conventional Node host.
