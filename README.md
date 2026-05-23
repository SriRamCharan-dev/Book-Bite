# Book & Bite

Book & Bite is a canteen food pre-booking web application with OTP-based signup/login, order management, and an admin dashboard.

## Features

- OTP-based user registration and verification
- JWT-based authentication for users and admin
- Browse menu and place orders
- User profile and order history
- Admin dashboard with order status updates
- Admin-managed special menu items
- Email notifications for OTP, order confirmation, and order status changes
- Basic rate limiting for OTP and login endpoints

## Tech Stack

- **Backend:** Node.js, Express, MongoDB (Mongoose)
- **Auth/Security:** JWT, bcryptjs, express-rate-limit
- **Email:** Nodemailer
- **Logging:** Winston
- **Frontend:** Static HTML/CSS/JS pages in `public/`
- **Deployment:** Vercel-compatible API (`api/index.js`)

## Project Structure

```text
Book-Bite/
├── api/
│   └── index.js          # Express API (Vercel entrypoint)
├── public/               # Static frontend pages and assets
├── .env.example          # Environment variable template
├── package.json
└── vercel.json
```

## Prerequisites

- Node.js (project declares `24.x` in `package.json`)
- npm
- MongoDB (local instance or MongoDB Atlas)

## Setup

1. Clone the repository and move into it.
2. Install dependencies:

   ```bash
   npm install
   ```

3. Create `.env` from `.env.example` and fill in values:

   ```bash
   cp .env.example .env
   ```

4. Start the server:

   ```bash
   npm start
   ```

5. Open the app in your browser:
   - Local URL: `http://localhost:3000`
   - Login page: `http://localhost:3000/index.html`

## Environment Variables

See `.env.example` for the latest template.

| Variable | Description |
| --- | --- |
| `MONGODB_URI` | MongoDB connection string |
| `JWT_SECRET` | Secret used to sign JWT tokens |
| `EMAIL` | Sender email for Nodemailer |
| `EMAIL_PASSWORD` | App password/SMTP password |
| `SMTP_HOST` | SMTP host (default: `smtp.gmail.com`) |
| `SMTP_PORT` | SMTP port (default: `587`) |
| `ADMIN_EMAIL` | Admin login email |
| `ADMIN_PASSWORD` | Admin login password |
| `NODE_ENV` | Environment (`development` / `production`) |

## Main API Endpoints

### Auth

- `POST /api/send-otp` — send OTP to email
- `POST /api/verify-otp` — verify OTP and optionally complete signup with password
- `POST /api/login` — login user/admin and receive JWT

### User

- `GET /api/profile` — fetch logged-in user profile
- `PUT /api/profile` — update profile/preferences
- `GET /api/orders/history` — user order history
- `POST /api/orders` — place order

### Admin

- `GET /api/admin/dashboard` — dashboard summary
- `GET /api/admin/orders` — list/filter orders
- `PUT /api/admin/orders/:orderId` — update order status
- `POST /api/admin/menu/specials` — add special menu item
- `PUT /api/admin/menu/specials/:id` — update special menu item
- `DELETE /api/admin/menu/specials/:id` — delete special menu item

### Public

- `GET /api/health` — service health check
- `GET /api/menu/specials` — fetch specials

## Notes

- In non-production mode, OTP can be returned in API response for testing.
- Static files are served by Express in local mode; Vercel serves static assets in deployment.
