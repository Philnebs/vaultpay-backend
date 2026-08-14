const nodemailer = require('nodemailer');
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');

require('dotenv').config();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const axios = require('axios');

const app = express();
const JWT_SECRET = process.env.JWT_SECRET;

app.use(cors()); 
app.use(express.json());

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ Connected to MongoDB'))
  .catch(err => console.log('❌ Mongo Error:', err));

// User Schema
const UserSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  phone: String,
  password: String,
  account_number: { type: String, unique: true },
  bank_name: { type: String }, 
  account_name: { type: String },
  wallet_balance: { type: Number, default: 1000.00 },
  created_at: { type: Date, default: Date.now },
  transactionPin: { type: String },
  resetOtpCode: { type: String },
  resetOtpExpires: { type: Date },
  isVerified: { type: Boolean, default: false },
  otpCode: { type: String },
  otpExpires: { type: Date }
});

const User = mongoose.model('User', UserSchema);

// Transaction Model
const transactionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['credit', 'debit'], required: true },
  amount: { type: Number, required: true },
  description: { type: String, required: true },
  reference: { type: String, unique: true },
  status: { type: String, default: 'successful' },
  recipient: { type: String },
  date: { type: Date, default: Date.now }
});

const Transaction = mongoose.model('Transaction', transactionSchema);

// AUTH MIDDLEWARE
const auth = async (req, res, next) => {
  try {
    const token = req.header('Authorization');
    if (!token) return res.status(401).json({ error: "No token, access denied" });

    const decoded = jwt.verify(token.replace('Bearer ', ''), process.env.JWT_SECRET);
    req.user = { id: decoded.id }; 
    next();
  } catch (err) {
    res.status(401).json({ error: "Token is not valid" });
  }
};

// LIGHTWEIGHT KEEP-ALIVE PING ROUTE
app.get('/api/ping', (req, res) => {
  return res.status(200).json({ success: true, status: "alive" });
});

// FLUTTERWAVE WEBHOOK
app.post('/api/webhook/flutterwave', async (req, res) => {
  const secretHash = process.env.FLW_WEBHOOK_HASH;
  const signature = req.headers["verif-hash"];
  
  if (signature !== secretHash) {
    return res.status(401).json({ error: "Invalid signature" });
  }

  const event = req.body;
  console.log("Webhook event:", event.event);

  if (event.event === "virtual_account.credit") {
    const { account_number, amount, transaction_id } = event.data;
    // credit user wallet logic goes here
  }
  
  res.status(200).json({ status: "success" });
});

// STEP 1: VALIDATE DATA AND SEND OTP EMAIL
app.post('/api/register/initiate', async (req, res) => {
  try {
    const { name, email, phone, password, bvn } = req.body;
    if (!name || !email || !phone || !password || !bvn) {
      return res.status(400).json({ error: "All registration fields and BVN are required." });
    }
    const normalizedEmail = email.toLowerCase().trim();
    const existingUser = await User.findOne({ email: normalizedEmail });
    if (existingUser && existingUser.isVerified) {
      return res.status(400).json({ error: "Email is already registered on VaultPay." });
    }
    const registrationOtp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpiryTime = Date.now() + 15 * 60 * 1000;
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const combinedOtpAndBvn = `${registrationOtp}-${bvn.trim()}`;
    await User.findOneAndUpdate(
      { email: normalizedEmail },
      {
        name: name.trim(),
        phone: phone.trim(),
        password: hashedPassword,
        otpCode: combinedOtpAndBvn,
        otpExpires: otpExpiryTime,
        isVerified: false
      },
      { upsert: true, new: true }
    );
    await axios.post(
      'https://api.brevo.com/v3/smtp/email',
      {
        sender: { name: "VaultPay Security", email: "ichinegbo@gmail.com" },
        to: [{ email: normalizedEmail }],
        subject: "Verify Your VaultPay Account",
        htmlContent: `<p>Hello ${name},</p><p>Your registration verification code is: <strong>${registrationOtp}</strong>. It expires in 15 minutes.</p>`
      },
      { headers: { 'api-key': process.env.BREVO_API_KEY, 'Content-Type': 'application/json' }, timeout: 15000 }
    );
    console.log(`📩 Registration OTP sent to ${normalizedEmail}`);
    return res.status(200).json({ success: true, message: "Verification OTP sent to email." });
  } catch (err) {
    console.error("❌ Registration Initiation Failure:", err.message);
    return res.status(500).json({ error: "Failed to process registration entry.", details: err.message });
  }
});

// STEP 2: VERIFY CODE, RUN FLUTTERWAVE PIPELINE, AND ACTIVATE ACCOUNT
app.post('/api/register/verify', async (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp) return res.status(400).json({ error: "Email and OTP code are required." });

    const normalizedEmail = email.toLowerCase().trim();
    const user = await User.findOne({ email: normalizedEmail });
    if (!user) return res.status(400).json({ error: "Registration session not found." });
    if (user.isVerified) return res.status(400).json({ error: "Account is already verified." });
    if (!user.otpCode) return res.status(400).json({ error: "Verification session data missing. Restart registration." });
    if (user.account_number) return res.status(400).json({ error: "Account already has bank details." });

    const parts = user.otpCode.split('-');
    const savedOtp = parts[0];
    const cleanBvn = parts[1];

    if (savedOtp !== otp.toString().trim()) return res.status(400).json({ error: "Invalid verification code." });
    if (Date.now() > user.otpExpires) return res.status(400).json({ error: "Verification code has expired. Restart registration." });

    console.log(`⏳ OTP Verified! Generating bank details for ${normalizedEmail}...`);

    const nameParts = (user.name || "User VaultPay").split(" ");
    const firstName = nameParts[0] || "User";
    const lastName = nameParts.slice(1).join(" ") || "VaultPay";
    const cleanPhone = (user.phone || '').replace(/\D/g, '');

    const flwResponse = await axios.post(
      'https://api.flutterwave.com/v3/virtual-account-numbers',
      {
        email: normalizedEmail,
        is_permanent: true,
        bvn: cleanBvn,
        tx_ref: `VP-REF-${Date.now()}`,
        firstname: firstName,
        lastname: lastName,
        phonenumber: cleanPhone
      },
      { headers: { Authorization: `Bearer ${process.env.FLW_SECRET_KEY}`, 'Content-Type': 'application/json' }, timeout: 18000 }
    );

    if (flwResponse.data.status !== 'success') {
      return res.status(400).json({ error: "Fintech routing allocation failed. Check BVN metrics.", details: flwResponse.data.message });
    }

    const flwData = flwResponse.data;
    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "7d" });

    user.isVerified = true;
    user.account_number = flwData.data.account_number;
    user.bank_name = flwData.data.bank_name; 
    user.account_name = flwData.data.account_name;
    user.otpCode = undefined;
    user.otpExpires = undefined;
    user.wallet_balance = 1000.00;
    await user.save();

    console.log(`🚀 VaultPay Activated: ${user.account_number}`);

    return res.status(200).json({
      success: true,
      message: "Your email has been verified and your account is active!",
      token: token,
      user: {
        id: user._id,
        account_info: {
          account_number: user.account_number,
          bank_name: user.bank_name,
          holder_name: user.name
        }
      }
    });
  } catch (err) {
    const errorMsg = err.response?.data?.message || err.message;
    console.error("❌ Final Verification/Fintech Error:", errorMsg);
    return res.status(500).json({ error: "Verification pipeline crash.", details: errorMsg });
  }
});

// STEP 3: FETCH DYNAMIC BILLER PACKAGES VIA FLUTTERWAVE
app.get('/api/bills/packages', auth, async (req, res) => {
  try {
    const { billType, serviceProvider } = req.query;

    if (!billType || !serviceProvider) {
      return res.status(400).json({ error: "Missing billType or serviceProvider parameters." });
    }

    let flwBillerCode = '';
    const provider = serviceProvider.toLowerCase().trim();
    
    if (billType === 'cable') {
      if (provider.includes('dstv')) flwBillerCode = 'BIL119';
      else if (provider.includes('gotv')) flwBillerCode = 'BIL120';
      else if (provider.includes('startimes')) flwBillerCode = 'BIL123';
    } else if (billType === 'data') {
      if (provider.includes('mtn')) flwBillerCode = 'BIL104';
      else if (provider.includes('airtel')) flwBillerCode = 'BIL105';
      else if (provider.includes('glo')) flwBillerCode = 'BIL107';
      else if (provider.includes('9mobile')) flwBillerCode = 'BIL106';
    }

    if (!flwBillerCode) {
      return res.status(200).json({ success: true, packages: [] });
    }

    const response = await axios.get(
      `https://api.flutterwave.com/v3/billers/${flwBillerCode}/items`,
      {
        headers: {
          'Authorization': `Bearer ${process.env.FLW_SECRET_KEY}`,
          'Content-Type': 'application/json'
        },
        timeout: 15000
      }
    );

    if (response.data.status !== 'success') {
      return res.status(400).json({ error: "Failed to pull data packages from Flutterwave." });
    }

    const cleanPackages = response.data.data.map(item => ({
      name: `${item.name} (₦${item.amount})`,
 price: parseFloat(item.amount),
      code: item.biller_name
    }));
    return res.status(200).json({ success: true, packages: cleanPackages });
  } catch (err) {
    console.error("❌ Live Package Directory Error:", err.message);
    return res.status(500).json({ error: "Server failed to fetch active utility packages." });
  }
});

// STEP 4: LIVE FLUTTERWAVE BILLS PAYMENT PROXY ENDPOINT
app.post('/api/bills/pay', auth, async (req, res) => {
  try {
    const { billType, serviceProvider, amount, customerId, packageCode } = req.body;
    if (!billType || !serviceProvider || !amount || !customerId) {
      return res.status(400).json({ error: "Missing required billing payment parameters." });
    }
    const numericAmount = parseFloat(amount);
    if (isNaN(numericAmount) || numericAmount <= 0) {
      return res.status(400).json({ error: "Please provide a valid transaction amount." });
    }
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ error: "User session account context not found." });
    }
    if (user.wallet_balance < numericAmount) {
      return res.status(400).json({ error: "Insufficient wallet balance to perform this operation." });
    }
    let flwBillerCode = '';
    const provider = serviceProvider.toLowerCase().trim();
    switch (billType.toLowerCase()) {
      case 'airtime':
        if (provider.includes('mtn')) flwBillerCode = 'BIL099';
        else if (provider.includes('airtel')) flwBillerCode = 'BIL100';
        else if (provider.includes('glo')) flwBillerCode = 'BIL102';
        else if (provider.includes('9mobile')) flwBillerCode = 'BIL101';
        break;
      case 'data':
        if (provider.includes('mtn')) flwBillerCode = 'BIL104';
        else if (provider.includes('airtel')) flwBillerCode = 'BIL105';
        else if (provider.includes('glo')) flwBillerCode = 'BIL107';
        else if (provider.includes('9mobile')) flwBillerCode = 'BIL106';
        break;
      case 'cable':
        if (provider.includes('dstv')) flwBillerCode = 'BIL119';
        else if (provider.includes('gotv')) flwBillerCode = 'BIL120';
        else if (provider.includes('startimes')) flwBillerCode = 'BIL123';
        break;
      case 'electricity':
        if (provider.includes('ikedc')) flwBillerCode = 'BIL112';
        else if (provider.includes('ekedc')) flwBillerCode = 'BIL113';
        else if (provider.includes('aedc')) flwBillerCode = 'BIL114';
        break;
      case 'jamb':
        flwBillerCode = 'BIL125';
        break;
      case 'waec':
        flwBillerCode = 'BIL126';
        break;
      case 'betting':
        if (provider.includes('bet9ja')) flwBillerCode = 'BIL130';
        else if (provider.includes('sportybet')) flwBillerCode = 'BIL131';
        break;
      default:
        return res.status(400).json({ error: "Unsupported bill category type." });
    }
    if (!flwBillerCode) {
      return res.status(400).json({ error: `Provider mapping for ${serviceProvider} is incomplete.` });
    }
    const reference = `VP-BILL-${Date.now()}-${Math.floor(1000 + Math.random() * 9000)}`;
    console.log(`📡 Sending Live Bill Request to Flutterwave for user: ${user.email}`);
    // Call Flutterwave's production API v3 interface
    const flwResponse = await axios.post('https://api.flutterwave.com/v3/bills', {
      country: "NG",
      customer: customerId.trim(),
      amount: numericAmount,
      type: packageCode || flwBillerCode, // Uses explicit bouquet if provided
      reference: reference
    }, {
      headers: {
        'Authorization': `Bearer ${process.env.FLW_SECRET_KEY}`,
        'Content-Type': 'application/json'
      },
      timeout: 25000
    });
    if (flwResponse.data.status !== 'success') {
      return res.status(400).json({
        error: "Flutterwave pipeline rejected payment.",
        details: flwResponse.data.message
      });
    }
    // Deduct only after live processing succeeds
    user.wallet_balance -= numericAmount;
    await user.save();
    const description = `${billType.toUpperCase()} purchase via ${serviceProvider.toUpperCase()} for ${customerId}`;
    const newTransaction = new Transaction({
      userId: user._id,
      type: 'debit',
      amount: numericAmount,
      description: description,
      reference: reference,
      status: 'successful',
      recipient: customerId
    });
    await newTransaction.save();
    return res.status(200).json({
      success: true,
      message: flwResponse.data.message || "Bill payment processed successfully!",
      newBalance: user.wallet_balance,
      transaction: { reference: reference, description: description, amount: numericAmount }
    });
  } catch (err) {
    const errorResponse = err.response?.data?.message || err.message;
    console.error("❌ Live Flutterwave API Error:", errorResponse);
    return res.status(500).json({
      error: "Failed to fulfill live third-party billing request.",
      details: errorResponse
    });
  }
});

// WEB SERVICE INITIALIZATION PORT LISTENER
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 VaultPay Engine Running Live on Port ${PORT}`);
});