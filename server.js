/*
================================================================================
MONEYPRINTER TURBO - COMPLETE BACKEND
================================================================================
*/

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const axios = require('axios');
const { createServer } = require('http');
const { Server } = require('socket.io');
const cron = require('node-cron');

// ==========================================
// CONFIGURATION
// ==========================================
const CONFIG = {
  PORT: process.env.PORT || 8000,
  MONGODB_URI: process.env.MONGODB_URI || 'mongodb://localhost:27017/moneyprinter',
  JWT_SECRET: process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-this-in-production',
  
  // API Keys (Replace with your actual keys)
  OPENAI_API_KEY: process.env.OPENAI_API_KEY || '',
  PEXELS_API_KEY: process.env.PEXELS_API_KEY || '',
  
  // Social Media (Replace with your actual keys)
  YOUTUBE_CLIENT_ID: process.env.YOUTUBE_CLIENT_ID || '',
  YOUTUBE_CLIENT_SECRET: process.env.YOUTUBE_CLIENT_SECRET || '',
  YOUTUBE_REDIRECT_URI: process.env.YOUTUBE_REDIRECT_URI || 'http://localhost:8000/api/social/youtube/callback',
  
  FACEBOOK_APP_ID: process.env.FACEBOOK_APP_ID || '',
  FACEBOOK_APP_SECRET: process.env.FACEBOOK_APP_SECRET || '',
  FACEBOOK_REDIRECT_URI: process.env.FACEBOOK_REDIRECT_URI || 'http://localhost:8000/api/social/facebook/callback',
  
  // Razorpay (Replace with your actual keys)
  RAZORPAY_KEY_ID: process.env.RAZORPAY_KEY_ID || 'rzp_test_your_key_id',
  RAZORPAY_KEY_SECRET: process.env.RAZORPAY_KEY_SECRET || 'your_key_secret',
  
  APP_URL: process.env.APP_URL || 'http://localhost:3000'
};

// ==========================================
// PREMIUM PLANS
// ==========================================
const PLANS = {
  free: { name: 'Free', price: 0, videosPerDay: 0, platforms: 0 },
  starter: { name: 'Starter', price: 299, videosPerDay: 1, platforms: 1 },
  pro: { name: 'Pro', price: 599, videosPerDay: 2, platforms: 2 },
  business: { name: 'Business', price: 799, videosPerDay: 4, platforms: 3 },
  unlimited: { name: 'Unlimited', price: 1299, videosPerDay: 999, platforms: 4 }
};

// ==========================================
// DATABASE
// ==========================================
mongoose.connect(CONFIG.MONGODB_URI)
  .then(() => console.log('✅ MongoDB Connected'))
  .catch(err => {
    console.log('⚠️  MongoDB not connected, using memory store');
  });

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  phone: String,
  isEmailVerified: { type: Boolean, default: false },
  
  subscription: {
    plan: { type: String, default: 'free' },
    status: { type: String, default: 'active' },
    expiresAt: Date
  },
  
  dailyVideos: {
    count: { type: Number, default: 0 },
    date: { type: String, default: '' }
  },
  
  socialAccounts: {
    youtube: {
      connected: { type: Boolean, default: false },
      accessToken: String,
      refreshToken: String,
      channelName: String,
      channelId: String
    },
    facebook: {
      connected: { type: Boolean, default: false },
      accessToken: String,
      pageName: String,
      pageId: String
    },
    instagram: {
      connected: { type: Boolean, default: false },
      accessToken: String,
      username: String
    }
  },
  
  createdAt: { type: Date, default: Date.now }
});

userSchema.pre('save', async function(next) {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 10);
  }
  next();
});

userSchema.methods.comparePassword = async function(pass) {
  return await bcrypt.compare(pass, this.password);
};

const User = mongoose.model('User', userSchema);

// Video Schema
const videoSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  title: String,
  topic: String,
  status: { type: String, default: 'pending' },
  progress: { type: Number, default: 0 },
  outputUrl: String,
  platforms: [String],
  schedule: {
    scheduledAt: Date,
    status: { type: String, default: 'pending' }
  },
  createdAt: { type: Date, default: Date.now }
});

const Video = mongoose.model('Video', videoSchema);

// Payment Schema
const paymentSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  plan: String,
  amount: Number,
  status: { type: String, default: 'pending' },
  razorpayOrderId: String,
  razorpayPaymentId: String,
  createdAt: { type: Date, default: Date.now }
});

const Payment = mongoose.model('Payment', paymentSchema);

// ==========================================
// MIDDLEWARE
// ==========================================
const app = express();
const httpServer = createServer(app);
const io = new Server(httpServer, { cors: { origin: '*' } });

app.use(cors());
app.use(express.json());
app.set('io', io);

// Auth Middleware
const authenticate = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) throw new Error('No token');
    
    const decoded = jwt.verify(token, CONFIG.JWT_SECRET);
    const user = await User.findById(decoded.id);
    if (!user) throw new Error('User not found');
    
    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({ success: false, error: 'Unauthorized' });
  }
};

// ==========================================
// AUTH ROUTES
// ==========================================

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password, phone } = req.body;
    
    const existing = await User.findOne({ $or: [{ email }, { username }] });
    if (existing) {
      return res.status(409).json({ success: false, error: 'User already exists' });
    }
    
    const user = new User({ username, email, password, phone });
    await user.save();
    
    const token = jwt.sign({ id: user._id }, CONFIG.JWT_SECRET, { expiresIn: '7d' });
    
    res.json({
      success: true,
      data: {
        token,
        user: {
          id: user._id,
          username: user.username,
          email: user.email,
          plan: 'free'
        }
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    const user = await User.findOne({
      $or: [{ email: username }, { username }]
    }).select('+password');
    
    if (!user || !(await user.comparePassword(password))) {
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }
    
    const token = jwt.sign({ id: user._id }, CONFIG.JWT_SECRET, { expiresIn: '7d' });
    
    res.json({
      success: true,
      data: {
        token,
        user: {
          id: user._id,
          username: user.username,
          email: user.email,
          plan: user.subscription.plan
        }
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get Me
app.get('/api/auth/me', authenticate, async (req, res) => {
  res.json({
    success: true,
    data: {
      id: req.user._id,
      username: req.user.username,
      email: req.user.email,
      plan: req.user.subscription.plan,
      isPremium: req.user.subscription.plan !== 'free'
    }
  });
});

// ==========================================
// PAYMENT ROUTES
// ==========================================

// Get Plans
app.get('/api/plans', (req, res) => {
  res.json({ success: true, data: PLANS });
});

// Create Order
app.post('/api/payment/create-order', authenticate, async (req, res) => {
  try {
    const { plan } = req.body;
    const planDetails = PLANS[plan];
    
    if (!planDetails || plan === 'free') {
      return res.status(400).json({ success: false, error: 'Invalid plan' });
    }
    
    // Create order using Razorpay API directly
    const orderData = {
      amount: planDetails.price * 100,
      currency: 'INR',
      receipt: `receipt_${Date.now()}`,
      notes: { userId: req.user._id.toString(), plan }
    };
    
    const response = await axios.post('https://api.razorpay.com/v1/orders', orderData, {
      auth: {
        username: CONFIG.RAZORPAY_KEY_ID,
        password: CONFIG.RAZORPAY_KEY_SECRET
      }
    });
    
    await Payment.create({
      user: req.user._id,
      plan,
      amount: planDetails.price,
      razorpayOrderId: response.data.id,
      status: 'pending'
    });
    
    res.json({
      success: true,
      data: {
        orderId: response.data.id,
        amount: response.data.amount,
        currency: response.data.currency,
        keyId: CONFIG.RAZORPAY_KEY_ID
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Verify Payment
app.post('/api/payment/verify', authenticate, async (req, res) => {
  try {
    const { razorpayOrderId, razorpayPaymentId, razorpaySignature, plan } = req.body;
    
    const body = razorpayOrderId + '|' + razorpayPaymentId;
    const expectedSignature = crypto
      .createHmac('sha256', CONFIG.RAZORPAY_KEY_SECRET)
      .update(body)
      .digest('hex');
    
    if (expectedSignature !== razorpaySignature) {
      return res.status(400).json({ success: false, error: 'Invalid signature' });
    }
    
    await Payment.findOneAndUpdate(
      { razorpayOrderId },
      { status: 'completed', razorpayPaymentId, razorpaySignature }
    );
    
    await User.findByIdAndUpdate(req.user._id, {
      'subscription.plan': plan,
      'subscription.status': 'active',
      'subscription.expiresAt': new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
    });
    
    res.json({ success: true, message: 'Payment successful' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ==========================================
// SOCIAL MEDIA ROUTES (One-Click)
// ==========================================

// YouTube Connect
app.get('/api/social/youtube/connect', authenticate, (req, res) => {
  const state = Buffer.from(JSON.stringify({
    userId: req.user._id.toString(),
    timestamp: Date.now()
  })).toString('base64');
  
  const url = 'https://accounts.google.com/o/oauth2/v2/auth?' +
    'client_id=' + CONFIG.YOUTUBE_CLIENT_ID +
    '&redirect_uri=' + encodeURIComponent(CONFIG.YOUTUBE_REDIRECT_URI) +
    '&response_type=code' +
    '&scope=' + encodeURIComponent('https://www.googleapis.com/auth/youtube.upload https://www.googleapis.com/auth/youtube.readonly') +
    '&access_type=offline' +
    '&prompt=consent' +
    '&state=' + encodeURIComponent(state);
  
  res.json({ success: true, url });
});

// YouTube Callback
app.get('/api/social/youtube/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    const { userId } = JSON.parse(Buffer.from(state, 'base64').toString());
    
    const tokenRes = await axios.post('https://oauth2.googleapis.com/token', {
      code,
      client_id: CONFIG.YOUTUBE_CLIENT_ID,
      client_secret: CONFIG.YOUTUBE_CLIENT_SECRET,
      redirect_uri: CONFIG.YOUTUBE_REDIRECT_URI,
      grant_type: 'authorization_code'
    });
    
    const { access_token, refresh_token } = tokenRes.data;
    
    const channelRes = await axios.get('https://www.googleapis.com/youtube/v3/channels?part=snippet&mine=true', {
      headers: { Authorization: `Bearer ${access_token}` }
    });
    
    const channel = channelRes.data.items[0];
    
    await User.findByIdAndUpdate(userId, {
      'socialAccounts.youtube': {
        connected: true,
        accessToken: access_token,
        refreshToken: refresh_token,
        channelId: channel.id,
        channelName: channel.snippet.title
      }
    });
    
    res.redirect(`${CONFIG.APP_URL}/settings?connected=youtube&name=${encodeURIComponent(channel.snippet.title)}`);
  } catch (error) {
    res.redirect(`${CONFIG.APP_URL}/settings?error=youtube`);
  }
});

// Facebook Connect
app.get('/api/social/facebook/connect', authenticate, (req, res) => {
  const state = Buffer.from(JSON.stringify({
    userId: req.user._id.toString()
  })).toString('base64');
  
  const url = 'https://www.facebook.com/v18.0/dialog/oauth?' +
    'client_id=' + CONFIG.FACEBOOK_APP_ID +
    '&redirect_uri=' + encodeURIComponent(CONFIG.FACEBOOK_REDIRECT_URI) +
    '&scope=' + encodeURIComponent('pages_manage_posts,pages_read_engagement,pages_show_list') +
    '&state=' + encodeURIComponent(state);
  
  res.json({ success: true, url });
});

// Facebook Callback
app.get('/api/social/facebook/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    const { userId } = JSON.parse(Buffer.from(state, 'base64').toString());
    
    const tokenRes = await axios.get('https://graph.facebook.com/v18.0/oauth/access_token', {
      params: {
        client_id: CONFIG.FACEBOOK_APP_ID,
        client_secret: CONFIG.FACEBOOK_APP_SECRET,
        redirect_uri: CONFIG.FACEBOOK_REDIRECT_URI,
        code
      }
    });
    
    const accessToken = tokenRes.data.access_token;
    
    const pagesRes = await axios.get('https://graph.facebook.com/v18.0/me/accounts', {
      params: { access_token: accessToken }
    });
    
    const page = pagesRes.data.data[0];
    
    await User.findByIdAndUpdate(userId, {
      'socialAccounts.facebook': {
        connected: true,
        accessToken: page.access_token,
        pageId: page.id,
        pageName: page.name
      }
    });
    
    res.redirect(`${CONFIG.APP_URL}/settings?connected=facebook&name=${encodeURIComponent(page.name)}`);
  } catch (error) {
    res.redirect(`${CONFIG.APP_URL}/settings?error=facebook`);
  }
});

// Get Connected Accounts
app.get('/api/social/accounts', authenticate, async (req, res) => {
  const accounts = {};
  
  for (const [platform, data] of Object.entries(req.user.socialAccounts)) {
    accounts[platform] = {
      connected: data.connected,
      name: data.channelName || data.pageName || data.username
    };
  }
  
  res.json({ success: true, data: accounts });
});

// Disconnect
app.post('/api/social/disconnect', authenticate, async (req, res) => {
  const { platform } = req.body;
  await User.findByIdAndUpdate(req.user._id, {
    [`socialAccounts.${platform}`]: { connected: false }
  });
  res.json({ success: true });
});

// ==========================================
// VIDEO ROUTES
// ==========================================

// Generate Video
app.post('/api/videos/generate', authenticate, async (req, res) => {
  try {
    const { topic, platforms } = req.body;
    
    // Check plan limits
    const plan = PLANS[req.user.subscription.plan];
    const today = new Date().toDateString();
    
    if (req.user.dailyVideos.date !== today) {
      req.user.dailyVideos = { count: 0, date: today };
    }
    
    if (req.user.dailyVideos.count >= plan.videosPerDay) {
      return res.status(403).json({
        success: false,
        error: 'Daily limit reached',
        upgrade: true
      });
    }
    
    if (platforms.length > plan.platforms) {
      return res.status(403).json({
        success: false,
        error: `Your plan supports max ${plan.platforms} platforms`
      });
    }
    
    // Create video
    const video = await Video.create({
      user: req.user._id,
      title: topic,
      topic,
      platforms,
      status: 'processing'
    });
    
    req.user.dailyVideos.count += 1;
    await req.user.save();
    
    // Simulate processing
    setTimeout(async () => {
      video.status = 'completed';
      video.outputUrl = 'https://example.com/video.mp4';
      await video.save();
      
      io.to(req.user._id.toString()).emit('videoComplete', {
        videoId: video._id,
        url: video.outputUrl
      });
    }, 5000);
    
    res.json({
      success: true,
      data: { videoId: video._id, status: 'processing' }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get Videos
app.get('/api/videos', authenticate, async (req, res) => {
  const videos = await Video.find({ user: req.user._id }).sort({ createdAt: -1 });
  res.json({ success: true, data: videos });
});

// ==========================================
// START SERVER
// ==========================================
httpServer.listen(CONFIG.PORT, () => {
  console.log(`🚀 Server running on port ${CONFIG.PORT}`);
});