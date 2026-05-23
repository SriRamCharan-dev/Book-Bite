# Book-Bite

Book-Bite is a canteen food pre-booking web application with:
- a static frontend in `public/`
- a Node.js + Express API in `api/index.js`
- MongoDB for persistence

## Features
- Email OTP-based signup flow
- User login with JWT authentication
- Profile management
- Order placement and order history
- Admin order dashboard and status updates
- Special menu item management

## Tech Stack
- Node.js, Express
- MongoDB + Mongoose
- JWT, bcryptjs
- Nodemailer
- Winston logging

## Project Structure
```text
Book-Bite/
├── api/
│   └── index.js
├── public/
│   ├── index.html
│   ├── signup.html
│   ├── menu.html
│   └── ...
├── .env.example
├── package.json
└── vercel.json
```

## Prerequisites
- Node.js `24.x`
- npm
- MongoDB (local or Atlas)

## Environment Variables
Create a `.env` file using `.env.example` as reference:

```env
MONGODB_URI=
JWT_SECRET=
EMAIL=
EMAIL_PASSWORD=
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
ADMIN_EMAIL=
ADMIN_PASSWORD=
NODE_ENV=development
```

## Installation
```bash
npm install
```

## Run Locally
```bash
npm run dev
```

The API runs from `api/index.js` and static frontend files are served from `public/` in local mode.

## API Health Check
```http
GET /api/health
```

## Available Scripts
- `npm run start` – start the server
- `npm run dev` – run the server in development mode

> Note: This repository currently does not define dedicated lint or test scripts in `package.json`.

## Deployment
This project includes `vercel.json` rewrite rules to route `/api/*` requests to `api/index.js`.
