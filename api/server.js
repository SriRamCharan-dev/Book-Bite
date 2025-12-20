// server.js

require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const winston = require('winston');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('.'));

// -------------------- LOGGER SETUP --------------------
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' }),
    new winston.transports.Console({ format: winston.format.simple() })
  ]
});

// -------------------- RATE LIMITERS --------------------
const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 requests per window
  message: { message: 'Too many OTP requests, please try again later' },
  standardHeaders: true,
  legacyHeaders: false
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // 10 login attempts per window
  message: { message: 'Too many login attempts, please try again later' },
  standardHeaders: true,
  legacyHeaders: false
});

// -------------------- DATABASE CONNECTION --------------------
mongoose
  .connect('mongodb://127.0.0.1:27017/bookAndBite', {
    useNewUrlParser: true,
    useUnifiedTopology: true
  })
  .then(() => logger.info('MongoDB connected', { service: 'otp-service', timestamp: new Date().toISOString() }))
  .catch(err => logger.error('MongoDB connection failed', { error: err.message }));

// -------------------- SCHEMAS --------------------
// User Schema
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: function() { return this.verified; } }, // Only required if user is verified
  otp: { type: String },
  otpExpiry: { type: Date },
  verified: { type: Boolean, default: false },
  otpAttempts: { type: Number, default: 0 },
  lastOtpRequest: { type: Date },
  profile: {
    name: { type: String },
    phone: { type: String },
    address: { type: String },
    city: { type: String },
    state: { type: String },
    zipCode: { type: String },
    profilePicture: { type: String }
  },
  preferences: {
    notifications: { type: Boolean, default: true },
    marketingEmails: { type: Boolean, default: false }
  },
  createdAt: { type: Date, default: Date.now }
});

// Order Schema
const orderSchema = new mongoose.Schema({
  userId: { type: String, required: true },
  items: [{ 
    name: String, 
    price: Number, 
    quantity: Number,
    img: String
  }],
  totalAmount: { type: Number, required: true },
  tokenNumber: { type: Number, required: true },
  status: { type: String, default: 'Pending', enum: ['Pending', 'Processing', 'Completed', 'Cancelled'] },
  customerInfo: {
    name: String,
    phone: String,
    address: String,
    paymentMethod: String
  },
  orderDate: { type: Date, default: Date.now },
  estimatedDelivery: { type: Date }
});

// Menu Item Schema
const menuItemSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String },
  price: { type: Number, required: true },
  img: { type: String },
  isSpecial: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

// OTP Log Schema for audit
const otpLogSchema = new mongoose.Schema({
  email: { type: String, required: true },
  action: { type: String, required: true, enum: ['generated', 'verified', 'expired', 'max_attempts', 'failed'] },
  ipAddress: String,
  userAgent: String,
  timestamp: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Order = mongoose.model('Order', orderSchema);
const OtpLog = mongoose.model('OtpLog', otpLogSchema);
const MenuItem = mongoose.model('MenuItem', menuItemSchema);

// -------------------- NODEMAILER SETUP --------------------
// Prefer env-configurable SMTP; default to Gmail settings. Fallback to console transport when creds are missing.
const smtpHost = process.env.SMTP_HOST || 'smtp.gmail.com';
const smtpPort = process.env.SMTP_PORT ? Number(process.env.SMTP_PORT) : 587; // default to STARTTLS
const smtpSecure = process.env.SMTP_SECURE ? process.env.SMTP_SECURE === 'true' : smtpPort === 465;
const smtpHostIp = process.env.SMTP_HOST_IP; // optional: connect by IP but keep SNI
const emailUser = process.env.EMAIL;
const emailPass = process.env.EMAIL_PASSWORD;
const emailDisabled = (process.env.EMAIL_DISABLED || '').toLowerCase() === 'true';

let transporter = null;
if (!emailDisabled && emailUser && emailPass) {
  const baseSmtpOptions = {
    host: smtpHostIp || smtpHost,
    port: smtpPort,
    secure: smtpSecure,
    auth: { user: emailUser, pass: emailPass },
    // Force IPv4 to avoid common Windows/ISP IPv6 DNS issues
    family: 4,
    // Require TLS upgrade when using 587
    requireTLS: !smtpSecure,
    // Make network behavior resilient
    pool: true,
    maxConnections: 2,
    maxMessages: 50,
    connectionTimeout: 10000,
    socketTimeout: 10000,
    greetingTimeout: 10000
  };

  // Preserve SNI when connecting via IP
  if (smtpHostIp) {
    baseSmtpOptions.tls = { servername: smtpHost };
  }

  transporter = nodemailer.createTransport(baseSmtpOptions);

  // Verify transporter at startup to surface email configuration issues early
  transporter.verify((error) => {
    if (error) {
      logger.error('Email transporter verification failed', { error: error.message, host: smtpHost, hostIp: smtpHostIp, port: smtpPort, secure: smtpSecure });
    } else {
      logger.info('Email transporter is ready to send messages', { host: smtpHost, hostIp: smtpHostIp, port: smtpPort, secure: smtpSecure });
    }
  });
} else {
  if (emailDisabled) {
    logger.warn('EMAIL_DISABLED=true. Emails will be skipped.');
  } else {
    logger.warn('EMAIL/EMAIL_PASSWORD not set. Using console transport (emails will not actually be sent).');
  }
  transporter = nodemailer.createTransport({ jsonTransport: true });
}

// -------------------- HELPER FUNCTIONS --------------------
async function sendEmailWithRetry(mailOptions) {
  // Skip real sending when disabled or using jsonTransport
  if ((process.env.EMAIL_DISABLED || '').toLowerCase() === 'true') {
    logger.warn('EMAIL_DISABLED is true. Skipping email send.', { to: mailOptions.to, subject: mailOptions.subject });
    return true;
  }

  const maxAttempts = 3;
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    try {
      await transporter.sendMail(mailOptions);
      return true;
    } catch (error) {
      const isLast = attempt === maxAttempts;
      logger.error('Email send failed', { attempt, to: mailOptions.to, subject: mailOptions.subject, error: error.message });

      // On second attempt, try a secure Gmail fallback if we're using gmail host
      const usingGmail = (process.env.SMTP_HOST || 'smtp.gmail.com').includes('gmail');
      const haveCreds = process.env.EMAIL && process.env.EMAIL_PASSWORD;
      if (attempt === 2 && usingGmail && haveCreds) {
        try {
          const fallbackTransporter = nodemailer.createTransport({
            host: process.env.SMTP_HOST || 'smtp.gmail.com',
            port: 465,
            secure: true,
            auth: { user: process.env.EMAIL, pass: process.env.EMAIL_PASSWORD },
            family: 4,
            requireTLS: false,
            connectionTimeout: 10000,
            socketTimeout: 10000,
            greetingTimeout: 10000
          });
          await fallbackTransporter.sendMail(mailOptions);
          logger.info('Email sent via secure fallback (465).', { to: mailOptions.to });
          return true;
        } catch (fallbackError) {
          logger.error('Fallback email send failed', { error: fallbackError.message, to: mailOptions.to });
        }
      }

      if (isLast) return false;
      // brief backoff
      await new Promise(r => setTimeout(r, 500 * attempt));
    }
  }
  return false;
}

async function sendOTP(email, otp) {
  const mailOptions = {
    from: process.env.EMAIL,
    to: email,
    subject: 'Your OTP Code - Book & Bite 🍴',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
        <div style="text-align: center; margin-bottom: 20px;">
          <h2 style="color: #4a4a4a;">Book & Bite</h2>
        </div>
        <div style="background-color: #f9f9f9; padding: 15px; border-radius: 4px; margin-bottom: 20px;">
          <h3 style="margin-top: 0; color: #4a4a4a;">Your Verification Code</h3>
          <div style="font-size: 24px; font-weight: bold; letter-spacing: 5px; text-align: center; margin: 15px 0; color: #4a4a4a;">${otp}</div>
          <p style="margin-bottom: 0; color: #777;">This code will expire in 5 minutes.</p>
        </div>
        <p style="color: #777; font-size: 14px;">If you didn't request this code, please ignore this email.</p>
        <div style="text-align: center; margin-top: 20px; padding-top: 20px; border-top: 1px solid #e0e0e0; color: #777; font-size: 12px;">
          <p>© ${new Date().getFullYear()} Book & Bite. All rights reserved.</p>
        </div>
      </div>
    `
  };

  const sent = await sendEmailWithRetry(mailOptions);
  if (sent) logger.info(`OTP sent to ${email}`);
  else logger.error(`Failed to send OTP to ${email}`);
  return sent;
}

async function sendOrderConfirmationEmail(email, orderDetails) {
  const { orderId, tokenNumber, items, totalAmount, estimatedDelivery } = orderDetails;
  
  // Create items HTML
  const itemsHtml = items.map(item => 
    `<tr>
      <td style="padding: 10px; border-bottom: 1px solid #eee;">${item.name}</td>
      <td style="padding: 10px; border-bottom: 1px solid #eee; text-align: center;">${item.quantity}</td>
      <td style="padding: 10px; border-bottom: 1px solid #eee; text-align: right;">₹${(item.price * item.quantity).toFixed(2)}</td>
    </tr>`
  ).join('');

  const mailOptions = {
    from: process.env.EMAIL,
    to: email,
    subject: 'Book & Bite - Order Confirmation #' + tokenNumber,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
        <div style="text-align: center; margin-bottom: 20px;">
          <h2 style="color: #4a4a4a;">Thank You for Your Order!</h2>
        </div>
        
        <div style="background-color: #f9f9f9; padding: 15px; border-radius: 4px; margin-bottom: 20px;">
          <h3 style="margin-top: 0; color: #4a4a4a;">Order Details</h3>
          <p><strong>Order ID:</strong> ${orderId}</p>
          <p><strong>Token Number:</strong> ${tokenNumber}</p>
          <p><strong>Estimated Delivery:</strong> ${estimatedDelivery}</p>
        </div>
        
        <div style="margin-bottom: 20px;">
          <h3 style="color: #4a4a4a;">Order Summary</h3>
          <table style="width: 100%; border-collapse: collapse;">
            <thead>
              <tr style="background-color: #f2f2f2;">
                <th style="padding: 10px; text-align: left;">Item</th>
                <th style="padding: 10px; text-align: center;">Qty</th>
                <th style="padding: 10px; text-align: right;">Price</th>
              </tr>
            </thead>
            <tbody>
              ${itemsHtml}
              <tr>
                <td colspan="2" style="padding: 10px; text-align: right; font-weight: bold;">Total:</td>
                <td style="padding: 10px; text-align: right; font-weight: bold;">₹${totalAmount.toFixed(2)}</td>
              </tr>
            </tbody>
          </table>
        </div>
        
        <p style="color: #777;">If you have any questions about your order, please contact our customer service.</p>
        
        <div style="text-align: center; margin-top: 20px; padding-top: 20px; border-top: 1px solid #e0e0e0; color: #777; font-size: 12px;">
          <p>© ${new Date().getFullYear()} Book & Bite. All rights reserved.</p>
        </div>
      </div>
    `
  };

  const sent = await sendEmailWithRetry(mailOptions);
  if (sent) logger.info(`Order confirmation email sent to ${email} for order ${orderId}`);
  else logger.error(`Failed to send order confirmation to ${email}`);
  return sent;
}

async function sendOrderStatusEmail(email, orderDetails) {
  const { orderId, tokenNumber, status } = orderDetails;

  const mailOptions = {
    from: process.env.EMAIL,
    to: email,
    subject: `Book & Bite - Order ${orderId} is now ${status}`,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
        <div style="text-align: center; margin-bottom: 20px;">
          <h2 style="color: #4a4a4a;">Order Status Updated</h2>
        </div>
        <p style=\"color: #4a4a4a;\">Your order <strong>#${tokenNumber}</strong> status has changed to <strong>${status}</strong>.</p>
        <p style=\"color: #777; font-size: 14px;\">Thank you for ordering with Book & Bite!</p>
        <div style="text-align: center; margin-top: 20px; padding-top: 20px; border-top: 1px solid #e0e0e0; color: #777; font-size: 12px;">
          <p>© ${new Date().getFullYear()} Book & Bite. All rights reserved.</p>
        </div>
      </div>
    `
  };

  const sent = await sendEmailWithRetry(mailOptions);
  if (sent) logger.info(`Order status email sent to ${email} for order ${orderId} status ${status}`);
  else logger.error(`Failed to send order status email to ${email}`);
  return sent;
}

// -------------------- AUTH MIDDLEWARE --------------------
// Authentication middleware
const authenticateUser = (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ message: 'Authentication required. Please log in.' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
    req.user = decoded;
    next();
  } catch (error) {
    logger.error('Authentication error:', { error: error.message });
    return res.status(401).json({ message: 'Invalid or expired token. Please log in again.' });
  }
};

// Admin authorization middleware
const authorizeAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    logger.warn(`Unauthorized admin access attempt by user ID: ${req.user.id}`);
    return res.status(403).json({ message: 'Access denied. Admin privileges required.' });
  }
  next();
};

// -------------------- ROUTES --------------------
// Health check endpoint
app.get('/api/health', (req, res) => {
  res.status(200).json({ status: 'ok', message: 'API is running' });
});

// Send OTP
app.post('/api/send-otp', otpLimiter, async (req, res) => {
  try {
    const { email } = req.body;
    
    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ message: 'Invalid email format' });
    }
    
    // Check if user exists
    let user = await User.findOne({ email });
    
    // Generate a secure OTP
    const otp = crypto.randomInt(100000, 999999).toString();
    const otpExpiry = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes
    
    if (user) {
      // If user exists but is already verified, don't allow OTP generation
      if (user.verified) {
        return res.status(400).json({ message: 'Email is already verified. Please login.' });
      }
      
      // Track OTP attempts
      user.otp = otp;
      user.otpExpiry = otpExpiry;
      user.otpAttempts = 0; // Reset attempts for new OTP
      user.lastOtpRequest = new Date();
    } else {
      // Create new unverified user
      user = new User({
        email,
        otp,
        otpExpiry,
        verified: false,
        otpAttempts: 0,
        lastOtpRequest: new Date()
      });
    }
    
    await user.save();
    
    // Log OTP generation
    await new OtpLog({
      email,
      action: 'generated',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    }).save();
    
    // Send OTP via email
    const sent = await sendOTP(email, otp);
    if (!sent) {
      return res.status(500).json({ message: 'Failed to send OTP. Please try again.' });
    }
    
    // In non-production, return OTP for testing convenience
    const responseBody = { message: 'OTP sent successfully' };
    if (process.env.NODE_ENV !== 'production') {
      responseBody.testOtp = otp;
    }
    res.status(200).json(responseBody);
  } catch (error) {
    logger.error('Error sending OTP:', { error: error.message, stack: error.stack });
    res.status(500).json({ message: 'Failed to send OTP. Please try again.' });
  }
});

// Verify OTP
app.post('/api/verify-otp', async (req, res) => {
  try {
    const { email, otp, password } = req.body;
    
    // Validate inputs
    if (!email || !otp) {
      return res.status(400).json({ message: 'Email and OTP are required' });
    }
    
    // If this is final verification with password, validate password strength
    if (password && password.length < 8) {
      return res.status(400).json({ message: 'Password must be at least 8 characters long' });
    }
    
    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    // Check if user is already verified
    if (user.verified) {
      return res.status(400).json({ message: 'Email is already verified. Please login.' });
    }
    
    // Check OTP attempts
    if (user.otpAttempts >= 5) {
      // Log max attempts reached
      await new OtpLog({
        email,
        action: 'max_attempts',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent']
      }).save();
      
      return res.status(400).json({ message: 'Maximum OTP attempts reached. Please request a new OTP.' });
    }
    
    // Increment attempt counter
    user.otpAttempts += 1;
    await user.save();
    
    // Verify OTP
    if (user.otp !== otp) {
      // Log failed verification
      await new OtpLog({
        email,
        action: 'failed',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent']
      }).save();
      
      return res.status(400).json({ message: 'Invalid OTP' });
    }
    
    // Check if OTP is expired
    if (new Date() > user.otpExpiry) {
      // Log expired OTP
      await new OtpLog({
        email,
        action: 'expired',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent']
      }).save();
      
      return res.status(400).json({ message: 'OTP has expired. Please request a new one.' });
    }
    
    // If password is provided, hash and save it
    if (password) {
      // Use higher salt rounds for better security
      const salt = await bcrypt.genSalt(12);
      const hashedPassword = await bcrypt.hash(password, salt);
      
      user.password = hashedPassword;
      user.verified = true;
    }
    
    // Clear OTP fields
    user.otp = undefined;
    user.otpExpiry = undefined;
    user.otpAttempts = 0;
    
    await user.save();
    
    // Log successful verification
    await new OtpLog({
      email,
      action: 'verified',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    }).save();
    
    res.status(200).json({ 
      message: password ? 'Email verified and account created successfully' : 'OTP verified successfully',
      verified: user.verified
    });
  } catch (error) {
    logger.error('Error verifying OTP:', { error: error.message, stack: error.stack });
    res.status(500).json({ message: 'Server error' });
  }
});

// Login
app.post('login', loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check if this is an admin login
    const isAdminEmail = email === process.env.ADMIN_EMAIL || email === 'admin@example.edu';
    
    const user = await User.findOne({ email });
    if (!user) {
      // Create admin user if it doesn't exist yet
      if (isAdminEmail && password === (process.env.ADMIN_PASSWORD || 'admin123')) {
        // For admin, create a special token with admin role
        const adminToken = jwt.sign(
          { id: 'admin', role: 'admin' }, 
          process.env.JWT_SECRET || 'your-secret-key', 
          { expiresIn: '24h' }
        );
        
        logger.info(`Admin login successful: ${email}`);
        return res.status(200).json({ 
          token: adminToken, 
          userId: 'admin',
          role: 'admin'
        });
      }
      
      return res.status(404).json({ message: 'User not found' });
    }

    if (!user.verified) {
      return res.status(400).json({ message: 'Email not verified' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      logger.warn(`Failed login attempt for user: ${email}`);
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Determine if the user has admin role
    const role = isAdminEmail ? 'admin' : 'user';
    
    const token = jwt.sign(
      { id: user._id, role }, 
      process.env.JWT_SECRET || 'your-secret-key', 
      { expiresIn: '1h' }
    );

    logger.info(`User login successful: ${email}, role: ${role}`);
    res.status(200).json({ token, userId: user._id, role });
  } catch (error) {
    logger.error('Error in login:', { error: error.message, stack: error.stack });
    res.status(500).json({ message: 'Server error' });
  }
});

// Place order
app.post('/api/orders', authenticateUser, async (req, res) => {
  try {
    const { items, totalAmount, customerInfo } = req.body;
    const userId = req.user.id;

    // Generate a random 4-digit token number
    const tokenNumber = Math.floor(1000 + Math.random() * 9000);

    // Get current date for estimated delivery (24 hours from now)
    const orderDate = new Date();
    const estimatedDelivery = new Date(orderDate);
    estimatedDelivery.setHours(estimatedDelivery.getHours() + 24);

    // Idempotency: if a matching order exists for this user with same items & total in last 10s, return it
    const tenSecondsAgo = new Date(Date.now() - 10 * 1000);
    const recentDuplicate = await Order.findOne({
      userId,
      totalAmount,
      orderDate: { $gte: tenSecondsAgo },
      'items.name': { $exists: true }
    }).sort({ orderDate: -1 });
    if (recentDuplicate && JSON.stringify(recentDuplicate.items) === JSON.stringify(items)) {
      return res.status(201).json({
        message: 'Order placed successfully',
        orderId: recentDuplicate._id,
        tokenNumber: recentDuplicate.tokenNumber,
        estimatedDelivery: recentDuplicate.estimatedDelivery
      });
    }

    const newOrder = new Order({
      userId,
      items,
      totalAmount,
      tokenNumber,
      status: 'Pending',
      customerInfo: customerInfo || {},
      orderDate,
      estimatedDelivery
    });

    await newOrder.save();
    
    // Get user email for order confirmation (skip for admin token)
    let user = null;
    if (userId !== 'admin') {
      user = await User.findById(userId).catch(() => null);
    }
    if (user && user.email) {
      // Send order confirmation email
      await sendOrderConfirmationEmail(
        user.email, 
        {
          orderId: newOrder._id,
          tokenNumber,
          items,
          totalAmount,
          estimatedDelivery: estimatedDelivery.toLocaleDateString('en-US', {
            weekday: 'long',
            year: 'numeric',
            month: 'long',
            day: 'numeric'
          })
        }
      );
      logger.info(`Order confirmation email sent to ${user.email} for order ${newOrder._id}`);
    }
    
    // Emit real-time notification for admin dashboard (if using WebSockets)
    // This would be implemented with Socket.io in a production environment
    
    res.status(201).json({
      message: 'Order placed successfully',
      orderId: newOrder._id,
      tokenNumber,
      estimatedDelivery: estimatedDelivery
    });
  } catch (error) {
    logger.error('Error placing order:', { error: error.message, stack: error.stack });
    res.status(500).json({ message: 'Failed to place order. Please try again.' });
  }
});

// Get user profile
app.get('profile', authenticateUser, async (req, res) => {
  try {
    const userId = req.user.id;
    
    // Exclude sensitive information
    const user = await User.findById(userId).select('-password -otp -otpExpiry -otpAttempts');
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    res.status(200).json({ user });
  } catch (error) {
    logger.error('Error fetching user profile:', { error: error.message, stack: error.stack, userId: req.user.id });
    res.status(500).json({ message: 'Failed to fetch profile. Please try again.' });
  }
});

// Update user profile
app.put('profile', authenticateUser, async (req, res) => {
  try {
    const userId = req.user.id;
    const { profile, preferences } = req.body;
    
    // Only update allowed fields
    const updateData = {};
    if (profile) updateData.profile = profile;
    if (preferences) updateData.preferences = preferences;
    
    const user = await User.findByIdAndUpdate(
      userId,
      { $set: updateData },
      { new: true, runValidators: true }
    ).select('-password -otp -otpExpiry -otpAttempts');
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    res.status(200).json({ 
      message: 'Profile updated successfully',
      user 
    });
  } catch (error) {
    logger.error('Error updating user profile:', { error: error.message, stack: error.stack, userId: req.user.id });
    res.status(500).json({ message: 'Failed to update profile. Please try again.' });
  }
});

// Get user order history
app.get('orders/history', authenticateUser, async (req, res) => {
  try {
    const userId = req.user.id;
    
    const orders = await Order.find({ userId })
      .sort({ orderDate: -1 }) // Most recent first
      .select('-__v');
    
    res.status(200).json({ orders });
  } catch (error) {
    logger.error('Error fetching order history:', { error: error.message, stack: error.stack, userId: req.user.id });
    res.status(500).json({ message: 'Failed to fetch order history. Please try again.' });
  }
});

// Admin: Get all orders for dashboard
app.get('/api/admin/orders', authenticateUser, authorizeAdmin, async (req, res) => {
  try {
    const { status, startDate, endDate } = req.query;
    
    // Build filter object
    const filter = {};
    if (status) filter.status = status;
    
    // Add date range filter if provided
    if (startDate || endDate) {
      filter.orderDate = {};
      if (startDate) filter.orderDate.$gte = new Date(startDate);
      if (endDate) filter.orderDate.$lte = new Date(endDate);
    }
    
    const orders = await Order.find(filter)
      .sort({ orderDate: -1 })
      .populate('userId', 'email profile.name profile.phone')
      .select('-__v');
    
    res.status(200).json({ orders });
  } catch (error) {
    logger.error('Error fetching admin orders:', { error: error.message, stack: error.stack });
    res.status(500).json({ message: 'Failed to fetch orders. Please try again.' });
  }
});

// Admin: Dashboard summary
app.get('admin/dashboard', authenticateUser, authorizeAdmin, async (req, res) => {
  try {
    const orders = await Order.find().sort({ orderDate: -1 }).select('-__v');
    const totalOrders = orders.length;
    const totalRevenue = orders.reduce((sum, o) => sum + (o.totalAmount || 0), 0);
    const pendingOrders = orders.filter(o => o.status === 'Pending').length;
    const completedOrders = orders.filter(o => o.status === 'Completed').length;
    const recentOrders = orders.slice(0, 5).map(o => ({
      id: String(o._id),
      tokenNumber: o.tokenNumber,
      items: o.items || [],
      totalAmount: o.totalAmount || 0,
      status: o.status,
      createdAt: o.orderDate
    }));

    res.status(200).json({
      totalOrders,
      totalRevenue,
      pendingOrders,
      completedOrders,
      recentOrders
    });
  } catch (error) {
    logger.error('Error fetching admin dashboard:', { error: error.message, stack: error.stack });
    res.status(500).json({ message: 'Failed to fetch dashboard data. Please try again.' });
  }
});

// Admin: Update order status
app.put('admin/orders/:orderId', authenticateUser, authorizeAdmin, async (req, res) => {
  try {
    const { orderId } = req.params;
    const { status } = req.body;
    
    if (!['Pending', 'Processing', 'Completed', 'Cancelled'].includes(status)) {
      return res.status(400).json({ message: 'Invalid order status' });
    }
    
    const order = await Order.findByIdAndUpdate(
      orderId,
      { $set: { status } },
      { new: true }
    );
    
    if (!order) {
      return res.status(404).json({ message: 'Order not found' });
    }
    
    // Notify user about order status change via email (if user exists and not admin)
    if (order && order.userId && order.userId !== 'admin') {
      const user = await User.findById(order.userId).catch(() => null);
      if (user && user.email) {
        await sendOrderStatusEmail(user.email, {
          orderId: order._id,
          tokenNumber: order.tokenNumber,
          status: order.status
        });
      }
    }
    
    res.status(200).json({ 
      message: 'Order status updated successfully',
      order 
    });
  } catch (error) {
    logger.error('Error updating order status:', { error: error.message, stack: error.stack });
    res.status(500).json({ message: 'Failed to update order status. Please try again.' });
  }
});

// Legacy update order status endpoint - maintained for backward compatibility
app.put('orders/:id', authenticateUser, authorizeAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    const order = await Order.findByIdAndUpdate(
      id,
      { status },
      { new: true }
    );

    if (!order) {
      return res.status(404).json({ message: 'Order not found' });
    }

    logger.info(`Order ${id} status updated to ${status}`);

    // Notify user about order status change via email (if user exists and not admin)
    if (order && order.userId && order.userId !== 'admin') {
      const user = await User.findById(order.userId).catch(() => null);
      if (user && user.email) {
        await sendOrderStatusEmail(user.email, {
          orderId: order._id,
          tokenNumber: order.tokenNumber,
          status: order.status
        });
      }
    }

    res.status(200).json(order);
  } catch (error) {
    logger.error('Error updating order:', { error: error.message, stack: error.stack });
    res.status(500).json({ message: 'Server error' });
  }
});

// Get all orders (for admin) - Legacy endpoint, maintained for backward compatibility
app.get('orders', authenticateUser, authorizeAdmin, async (req, res) => {
  try {
    const orders = await Order.find().sort({ orderDate: -1 });
    res.status(200).json(orders);
  } catch (error) {
    logger.error('Error fetching orders:', { error: error.message, stack: error.stack });
    res.status(500).json({ message: 'Server error' });
  }
});

// -------------------- MENU MANAGEMENT --------------------
// Create or update a special menu item (admin only)
app.post('/api/admin/menu/specials', authenticateUser, authorizeAdmin, async (req, res) => {
  try {
    const { name, description, price, img } = req.body;
    if (!name || typeof price !== 'number') {
      return res.status(400).json({ message: 'Name and numeric price are required' });
    }
    const item = new MenuItem({ name, description: description || '', price, img: img || '', isSpecial: true });
    await item.save();
    res.status(201).json({ message: 'Special item added', item });
  } catch (error) {
    logger.error('Error creating special menu item:', { error: error.message });
    res.status(500).json({ message: 'Failed to add special item' });
  }
});

// Get specials (public)
app.get('menu/specials', async (req, res) => {
  try {
    const items = await MenuItem.find({ isSpecial: true }).sort({ createdAt: -1 }).select('-__v');
    res.status(200).json({ items });
  } catch (error) {
    logger.error('Error fetching specials:', { error: error.message });
    res.status(500).json({ message: 'Failed to fetch specials' });
  }
});

// Update a special (admin only)
app.put('admin/menu/specials/:id', authenticateUser, authorizeAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, price, img } = req.body;
    const update = {};
    if (name !== undefined) update.name = name;
    if (description !== undefined) update.description = description;
    if (price !== undefined) update.price = price;
    if (img !== undefined) update.img = img;
    const item = await MenuItem.findByIdAndUpdate(id, { $set: update }, { new: true });
    if (!item) return res.status(404).json({ message: 'Item not found' });
    res.status(200).json({ message: 'Special updated', item });
  } catch (error) {
    logger.error('Error updating special:', { error: error.message });
    res.status(500).json({ message: 'Failed to update special' });
  }
});

// Delete a special (admin only)
app.delete('admin/menu/specials/:id', authenticateUser, authorizeAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const deleted = await MenuItem.findByIdAndDelete(id);
    if (!deleted) return res.status(404).json({ message: 'Item not found' });
    res.status(200).json({ message: 'Special deleted' });
  } catch (error) {
    logger.error('Error deleting special:', { error: error.message });
    res.status(500).json({ message: 'Failed to delete special' });
  }
});
// -------------------- SERVER START --------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  logger.info(`Server running on port ${PORT}`);
});
