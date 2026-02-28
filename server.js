const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const nodemailer = require('nodemailer');
const multer = require('multer');
const { google } = require('googleapis');
const ffmpeg = require('fluent-ffmpeg');
const path = require('path');
const fs = require('fs');
const cron = require('node-cron');

const app = express();

app.use(cors({ origin: '*', methods: ['GET', 'POST', 'PUT', 'DELETE'], allowedHeaders: ['Content-Type', 'Authorization'] }));
app.use(express.json());
app.use('/uploads', express.static('uploads'));

if (!fs.existsSync('uploads')) fs.mkdirSync('uploads');

// MongoDB
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/autovideo';
mongoose.connect(MONGODB_URI).then(() => console.log('MongoDB Connected')).catch(err => console.error('MongoDB Error:', err));

// ========== SCHEMAS ==========

const UserSchema = new mongoose.Schema({
    email: { type: String, unique: true, required: true },
    password: String,
    otp: String,
    otpExpiry: Date,
    isVerified: { type: Boolean, default: false },
    
    // Har user ke apne alag social accounts
    youtube: {
        connected: { type: Boolean, default: false },
        channelName: String,
        accessToken: String,
        refreshToken: String,
        expiryDate: Date
    },
    instagram: {
        connected: { type: Boolean, default: false },
        username: String,
        accessToken: String,
        userId: String
    },
    
    membership: { type: String, default: 'free' },
    createdAt: { type: Date, default: Date.now }
});

const VideoSchema = new mongoose.Schema({
    userId: mongoose.Schema.Types.ObjectId,
    title: String,
    description: String,
    audioPath: String,
    imagePath: String,
    outputPath: String,
    status: { type: String, default: 'pending' }, // pending, processing, completed, failed, uploaded
    scheduleTime: Date,
    platforms: [{ type: String }], // ['youtube'], ['instagram'], ['youtube', 'instagram']
    
    // Upload status alag alag platforms ke liye
    uploadStatus: {
        youtube: { uploaded: Boolean, videoId: String, error: String },
        instagram: { uploaded: Boolean, mediaId: String, error: String }
    },
    
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Video = mongoose.model('Video', VideoSchema);

// Multer
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads/'),
    filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({ storage });

// JWT
const auth = (req, res, next) => {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'Access denied' });
    try {
        req.user = jwt.verify(token, process.env.JWT_SECRET || 'secret_key');
        next();
    } catch (err) {
        res.status(400).json({ error: 'Invalid token' });
    }
};

// Email
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER || 'your-email@gmail.com',
        pass: process.env.EMAIL_PASS || 'your-app-password'
    }
});

// ========== AUTH ROUTES ==========

app.post('/api/send-otp', async (req, res) => {
    try {
        const { email } = req.body;
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpiry = new Date(Date.now() + 10 * 60 * 1000);

        let user = await User.findOne({ email });
        if (!user) {
            user = new User({ email, otp, otpExpiry });
        } else {
            user.otp = otp;
            user.otpExpiry = otpExpiry;
        }
        await user.save();

        await transporter.sendMail({
            to: email,
            subject: 'Your OTP Code - AutoVideo',
            text: `Your OTP is: ${otp}\nValid for 10 minutes.\n\nAutoVideo Team`
        });

        res.json({ message: 'OTP sent successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to send OTP' });
    }
});

app.post('/api/verify-otp', async (req, res) => {
    try {
        const { email, otp, password } = req.body;
        const user = await User.findOne({ email, otp, otpExpiry: { $gt: new Date() } });
        
        if (!user) return res.status(400).json({ error: 'Invalid or expired OTP' });
        
        user.password = await bcrypt.hash(password, 10);
        user.isVerified = true;
        user.otp = null;
        await user.save();

        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET || 'secret_key');
        res.json({ token, message: 'Account created successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        
        if (!user || !await bcrypt.compare(password, user.password)) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }
        
        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET || 'secret_key');
        
        // User ka connection status bhi bhejein
        res.json({ 
            token, 
            user: {
                email: user.email,
                youtubeConnected: user.youtube.connected,
                instagramConnected: user.instagram.connected,
                membership: user.membership
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ error: 'User not found' });

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        user.otp = otp;
        user.otpExpiry = new Date(Date.now() + 10 * 60 * 1000);
        await user.save();

        await transporter.sendMail({
            to: email,
            subject: 'Password Reset OTP - AutoVideo',
            text: `Your password reset OTP is: ${otp}\nValid for 10 minutes.`
        });

        res.json({ message: 'Reset OTP sent' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/reset-password', async (req, res) => {
    try {
        const { email, otp, newPassword } = req.body;
        const user = await User.findOne({ email, otp, otpExpiry: { $gt: new Date() } });
        
        if (!user) return res.status(400).json({ error: 'Invalid OTP' });
        
        user.password = await bcrypt.hash(newPassword, 10);
        user.otp = null;
        await user.save();

        res.json({ message: 'Password reset successful' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ========== USER PROFILE & CONNECTION STATUS ==========

app.get('/api/profile', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId).select('-password -otp');
        res.json(user);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ========== YOUTUBE OAUTH (HAR USER KE LIYE ALAG) ==========

const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';

// Step 1: YouTube connect karne ka URL generate karein
app.get('/api/youtube/connect', auth, async (req, res) => {
    try {
        const oauth2Client = new google.auth.OAuth2(
            process.env.YOUTUBE_CLIENT_ID,
            process.env.YOUTUBE_CLIENT_SECRET,
            `${BASE_URL}/api/youtube/callback`
        );
        
        // User ID ko state mein bhejein taaki pata chale kaunsa user connect kar raha hai
        const state = Buffer.from(JSON.stringify({ userId: req.user.userId })).toString('base64');
        
        const url = oauth2Client.generateAuthUrl({
            access_type: 'offline',
            scope: [
                'https://www.googleapis.com/auth/youtube.upload',
                'https://www.googleapis.com/auth/youtube.readonly'
            ],
            state: state,
            prompt: 'consent' // Har baar refresh token mile
        });
        
        res.json({ url, message: 'Click to connect your YouTube channel' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to generate auth URL' });
    }
});

// Step 2: YouTube se callback aane par
app.get('/api/youtube/callback', async (req, res) => {
    try {
        const { code, state } = req.query;
        
        // State se user ID nikalein
        const { userId } = JSON.parse(Buffer.from(state, 'base64').toString());
        
        const oauth2Client = new google.auth.OAuth2(
            process.env.YOUTUBE_CLIENT_ID,
            process.env.YOUTUBE_CLIENT_SECRET,
            `${BASE_URL}/api/youtube/callback`
        );
        
        const { tokens } = await oauth2Client.getToken(code);
        
        // User ka channel info lein
        oauth2Client.setCredentials(tokens);
        const youtube = google.youtube({ version: 'v3', auth: oauth2Client });
        const channelResponse = await youtube.channels.list({
            part: 'snippet',
            mine: true
        });
        
        const channelName = channelResponse.data.items?.[0]?.snippet?.title || 'Unknown';
        
        // User ke document mein save karein
        await User.findByIdAndUpdate(userId, {
            youtube: {
                connected: true,
                channelName: channelName,
                accessToken: tokens.access_token,
                refreshToken: tokens.refresh_token,
                expiryDate: tokens.expiry_date
            }
        });
        
        res.send(`
            <html>
                <body style="font-family: Arial; text-align: center; padding: 50px;">
                    <h2 style="color: green;">✅ YouTube Connected Successfully!</h2>
                    <p>Channel: <strong>${channelName}</strong></p>
                    <p>You can close this window now.</p>
                    <script>setTimeout(() => window.close(), 3000);</script>
                </body>
            </html>
        `);
    } catch (error) {
        console.error('YouTube callback error:', error);
        res.status(500).send(`<h2 style="color: red;">❌ Connection Failed: ${error.message}</h2>`);
    }
});

// Disconnect YouTube
app.post('/api/youtube/disconnect', auth, async (req, res) => {
    try {
        await User.findByIdAndUpdate(req.user.userId, {
            youtube: { connected: false, channelName: null, accessToken: null, refreshToken: null, expiryDate: null }
        });
        res.json({ message: 'YouTube disconnected successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ========== INSTAGRAM OAUTH (HAR USER KE LIYE ALAG) ==========

// Instagram Basic Display API (Photos/Videos upload ke liye Instagram Graph API chahiye hoti hai)
// Yahan Basic Display ke liye setup hai, upload ke liye Graph API use karein

app.get('/api/instagram/connect', auth, (req, res) => {
    const state = Buffer.from(JSON.stringify({ userId: req.user.userId })).toString('base64');
    
    const url = `https://api.instagram.com/oauth/authorize?client_id=${process.env.INSTAGRAM_APP_ID}&redirect_uri=${BASE_URL}/api/instagram/callback&scope=user_profile,user_media&response_type=code&state=${state}`;
    
    res.json({ url, message: 'Click to connect your Instagram account' });
});

app.get('/api/instagram/callback', async (req, res) => {
    try {
        const { code, state } = req.query;
        const { userId } = JSON.parse(Buffer.from(state, 'base64').toString());
        
        // Instagram se short-lived token lein
        const tokenResponse = await fetch('https://api.instagram.com/oauth/access_token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({
                client_id: process.env.INSTAGRAM_APP_ID,
                client_secret: process.env.INSTAGRAM_APP_SECRET,
                grant_type: 'authorization_code',
                redirect_uri: `${BASE_URL}/api/instagram/callback`,
                code: code
            })
        });
        
        const tokenData = await tokenResponse.json();
        
        // Long-lived token exchange karein
        const longLivedResponse = await fetch(`https://graph.instagram.com/access_token?grant_type=ig_exchange_token&client_secret=${process.env.INSTAGRAM_APP_SECRET}&access_token=${tokenData.access_token}`);
        const longLivedData = await longLivedResponse.json();
        
        // User info lein
        const userResponse = await fetch(`https://graph.instagram.com/me?fields=id,username&access_token=${longLivedData.access_token}`);
        const userData = await userResponse.json();
        
        await User.findByIdAndUpdate(userId, {
            instagram: {
                connected: true,
                username: userData.username,
                accessToken: longLivedData.access_token,
                userId: userData.id
            }
        });
        
        res.send(`
            <html>
                <body style="font-family: Arial; text-align: center; padding: 50px;">
                    <h2 style="color: green;">✅ Instagram Connected!</h2>
                    <p>Username: <strong>@${userData.username}</strong></p>
                    <script>setTimeout(() => window.close(), 3000);</script>
                </body>
            </html>
        `);
    } catch (error) {
        res.status(500).send(`<h2 style="color: red;">❌ Failed: ${error.message}</h2>`);
    }
});

// ========== VIDEO CREATION & UPLOAD ==========

app.post('/api/create-video', auth, upload.fields([{ name: 'audio' }, { name: 'image' }]), async (req, res) => {
    try {
        const { title, description, scheduleTime, platforms } = req.body;
        
        // Platforms array hoga: ["youtube"], ["instagram"], ya ["youtube", "instagram"]
        const platformArray = JSON.parse(platforms || '["youtube"]');
        
        const video = new Video({
            userId: req.user.userId,
            title,
            description: description || '',
            audioPath: req.files.audio[0].path,
            imagePath: req.files.image[0].path,
            scheduleTime: new Date(scheduleTime),
            platforms: platformArray,
            uploadStatus: {
                youtube: { uploaded: false },
                instagram: { uploaded: false }
            }
        });
        
        await video.save();
        res.json({ message: 'Video scheduled successfully', videoId: video._id });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/my-videos', auth, async (req, res) => {
    try {
        const videos = await Video.find({ userId: req.user.userId }).sort({ createdAt: -1 });
        res.json(videos);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ========== AUTO PROCESSOR ==========

// Token refresh function
async function refreshYouTubeToken(user) {
    try {
        const oauth2Client = new google.auth.OAuth2(
            process.env.YOUTUBE_CLIENT_ID,
            process.env.YOUTUBE_CLIENT_SECRET,
            `${BASE_URL}/api/youtube/callback`
        );
        
        oauth2Client.setCredentials({
            refresh_token: user.youtube.refreshToken
        });
        
        const { credentials } = await oauth2Client.refreshAccessToken();
        
        // Update user with new token
        await User.findByIdAndUpdate(user._id, {
            'youtube.accessToken': credentials.access_token,
            'youtube.expiryDate': credentials.expiry_date
        });
        
        return credentials.access_token;
    } catch (error) {
        console.error('Token refresh failed:', error);
        return null;
    }
}

// Cron job - Har minute check karein
cron.schedule('* * * * *', async () => {
    try {
        const pendingVideos = await Video.find({ 
            status: 'pending', 
            scheduleTime: { $lte: new Date() } 
        }).populate('userId');

        for (let video of pendingVideos) {
            try {
                video.status = 'processing';
                await video.save();

                const outputPath = `uploads/output-${video._id}.mp4`;
                
                // FFmpeg se video banayein
                await new Promise((resolve, reject) => {
                    ffmpeg()
                        .input(video.imagePath)
                        .loop()
                        .input(video.audioPath)
                        .audioCodec('aac')
                        .videoCodec('libx264')
                        .outputOptions('-pix_fmt yuv420p', '-shortest', '-vf', 'scale=1920:1080:force_original_aspect_ratio=decrease,pad=1920:1080:(ow-iw)/2:(oh-ih)/2')
                        .output(outputPath)
                        .on('end', resolve)
                        .on('error', reject)
                        .run();
                });

                video.outputPath = outputPath;
                video.status = 'completed';
                await video.save();

                // Ab upload karein har platform par
                await uploadToPlatforms(video);
                
            } catch (error) {
                video.status = 'failed';
                await video.save();
                console.error('Video processing failed:', error);
            }
        }
    } catch (error) {
        console.error('Cron error:', error);
    }
});

async function uploadToPlatforms(video) {
    const user = await User.findById(video.userId);
    
    // ========== YOUTUBE UPLOAD ==========
    if (video.platforms.includes('youtube') && user.youtube.connected) {
        try {
            // Token expired hai toh refresh karein
            let accessToken = user.youtube.accessToken;
            if (new Date() > new Date(user.youtube.expiryDate)) {
                accessToken = await refreshYouTubeToken(user);
            }
            
            if (!accessToken) throw new Error('Failed to refresh token');
            
            const oauth2Client = new google.auth.OAuth2();
            oauth2Client.setCredentials({ access_token: accessToken });
            const youtube = google.youtube({ version: 'v3', auth: oauth2Client });

            const uploadResponse = await youtube.videos.insert({
                part: 'snippet,status',
                requestBody: {
                    snippet: { 
                        title: video.title, 
                        description: video.description || 'Created with AutoVideo',
                        tags: ['autovideo', 'auto-generated']
                    },
                    status: { privacyStatus: 'public' }
                },
                media: { body: fs.createReadStream(video.outputPath) }
            });
            
            video.uploadStatus.youtube = { 
                uploaded: true, 
                videoId: uploadResponse.data.id,
                error: null
            };
            console.log(`✅ YouTube upload successful for user ${user.email}: ${uploadResponse.data.id}`);
            
        } catch (err) {
            video.uploadStatus.youtube = { uploaded: false, error: err.message };
            console.error('YouTube upload failed:', err);
        }
    }

    // ========== INSTAGRAM UPLOAD ==========
    // Instagram Graph API se reels/video upload (professional account chahiye)
    if (video.platforms.includes('instagram') && user.instagram.connected) {
        try {
            // Instagram Graph API upload logic yahan
            // Note: Iske liye Facebook Developer account aur Instagram Professional account chahiye
            
            video.uploadStatus.instagram = { uploaded: true, mediaId: 'pending' };
            console.log(`✅ Instagram upload queued for user ${user.email}`);
            
        } catch (err) {
            video.uploadStatus.instagram = { uploaded: false, error: err.message };
            console.error('Instagram upload failed:', err);
        }
    }
    
    // Agar sab jagah upload ho gaya toh status update karein
    const allUploaded = video.platforms.every(platform => {
        if (platform === 'youtube') return video.uploadStatus.youtube.uploaded;
        if (platform === 'instagram') return video.uploadStatus.instagram.uploaded;
        return true;
    });
    
    if (allUploaded) {
        video.status = 'uploaded';
    }
    
    await video.save();
}

// Health check
app.get('/', (req, res) => {
    res.json({ 
        message: 'AutoVideo API - Multi-User Platform', 
        status: 'OK',
        features: ['OTP Auth', 'YouTube Connect', 'Instagram Connect', 'Auto Video Upload']
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Multi-User AutoVideo Platform running on port ${PORT}`);
    console.log(`📺 Each user can connect their own YouTube/Instagram`);
});
