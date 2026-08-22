const Flutterwave = require('flutterwave-node-v3');
const Brevo = require('@getbrevo/brevo');
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const axios = require('axios');
require('dotenv').config();

// Syncs your local variable names with your Render dashboard keys
process.env.FLW_WEBHOOK_HASH = process.env.FLW_HASH_KEY;
const flw = new Flutterwave(process.env.FLW_PUBLIC_KEY, process.env.FLW_SECRET_KEY);

const app = express();
const JWT_SECRET = process.env.JWT_SECRET;

// Chunk 1: Flutterwave Biller Code Dictionary Mapping
// Updated Chunk 1: Automatic Environment-Aware Biller Codes
const isLive = process.env.FLW_SECRET_KEY && process.env.FLW_SECRET_KEY.startsWith("FLWSECK-");

const BILLER_CODES = {
  // Cable TV Operators
  'dstv': isLive ? 'BIL119' : 'BIL119', // (Note: If FLW uses same codes for test/live, keep them identical)
  'gotv': isLive ? 'BIL120' : 'BIL120',
  'startimes': isLive ? 'BIL121' : 'BIL121',
  
  // Electricity DisCos (Prepaid)
  'ikedc_prepaid': isLive ? 'BIL113' : 'BIL113', 
  'ekedc_prepaid': isLive ? 'BIL112' : 'BIL112', 
  'aedc_prepaid': isLive ? 'BIL111' : 'BIL111',  
  
  // Electricity DisCos (Postpaid)
  'ikedc_postpaid': isLive ? 'BIL117' : 'BIL117',
  'ekedc_postpaid': isLive ? 'BIL116' : 'BIL116',
  'aedc_postpaid': isLive ? 'BIL115' : 'BIL115'
};

// Chunk 2: Fetch Live Utility Packages Endpoint
app.get('/api/bills/packages', auth, async (req, res) => {
  try {
    const { operator } = req.query;

    if (!operator) {
      return res.status(400).json({ error: "Operator parameter is required." });
    }

    // Look up the official code from our dictionary mapping
    const billerCode = BILLER_CODES[operator.toLowerCase()];
    if (!billerCode) {
      return res.status(400).json({ error: "Unsupported utility provider operator." });
    }

    // Hit Flutterwave's live biller items catalog registry
    const response = await axios.get(
      `https://api.flutterwave.com/v3/billers/${billerCode}/items`,
      {
        headers: { Authorization: `Bearer ${process.env.FLW_SECRET_KEY}` },
        timeout: 15000
      }
    );

    // Filter, map, and clean up the incoming data structure for your frontend
    const cleanPackages = response.data.data.map(item => ({
      name: item.name,
      price: item.amount,
      biller_code: billerCode,
      item_code: item.item_code
    }));

    return res.status(200).json({ success: true, packages: cleanPackages });

  } catch (err) {
    const errorMsg = err.response?.data?.message || err.message;
    return res.status(500).json({ error: "Failed to pull live provider packages.", details: errorMsg });
  }
});



app.use(cors());
app.use(express.json());

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ Connected to MongoDB'))
  .catch(err => console.log('❌ Mongo Error:', err));

  const UserSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  phone: String,
  password: String,
  bvn: { type: String },

  account_number: { type: String, unique: true },
  bank_name: { type: String }, 
  account_name: { type: String },
  wallet_balance: { type: Number, default: 0.00 },
  transactionPin: { type: String },
  isVerified: { type: Boolean, default: false },
  otpCode: { type: String },
  otpExpires: { type: Date },
  resetOtpCode: { type: String },
  resetOtpExpires: { type: Date },
  created_at: { type: Date, default: Date.now },
    
});

const User = mongoose.model('User', UserSchema);

const transactionSchema = new mongoose.Schema({
  user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['Bank Transfer', 'Deposit', 'Airtime', 'Data'], required: true },
  amount: { type: Number, required: true },
  description: { type: String, required: true },
  recipient_account: { type: String },
  recipient_bank: { type: String },
  sender_name: { type: String },
  reference: { type: String, unique: true },
  status: { type: String, enum: ['PENDING', 'SUCCESSFUL', 'FAILED'], default: 'PENDING' },
  created_at: { type: Date, default: Date.now }
});

const Transaction = mongoose.model('Transaction', transactionSchema);

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
app.get('/api/ping', (req, res) => {
  return res.status(200).json({ success: true, status: "alive" });
});

app.post('/api/register/initiate', async (req, res) => {
  try {
    const { name, email, phone, password, bvn } = req.body;
    if (!name || !email || !phone || !password || !bvn) {
      return res.status(400).json({ error: "All profile registration parameters and BVN are required." });
    }
    
    const normalizedEmail = email.toLowerCase().trim();
    const existingUser = await User.findOne({ email: normalizedEmail });
    if (existingUser && existingUser.isVerified) {
      return res.status(400).json({ error: "This email address is already fully registered." });
    }

    const registrationOtp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpiryTime = Date.now() + 15 * 60 * 1000;
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    // Saves entry parameters including bvn to database mapping cache
    await User.findOneAndUpdate(
      { email: normalizedEmail },
      {
        name: name.trim(),
        phone: phone.trim(),
        password: hashedPassword,
        bvn: bvn.toString().trim(), // Cache bvn string values smoothly here
        otpCode: registrationOtp,
        otpExpires: otpExpiryTime,
        isVerified: false
      },
      { upsert: true, returnDocument: 'after' }
    );

    console.log(`📧 Sending Brevo OTP Registration Email to: ${normalizedEmail}`);

    await axios.post(
      'https://api.brevo.com/v3/smtp/email',
      {
        sender: { name: "VaultPay Security", email: "ichinegbo@gmail.com" },
        to: [{ email: normalizedEmail }],
        subject: "Verify Your VaultPay Account",
        htmlContent: `<p>Hello ${name.trim()},</p><p>Your registration code is: <strong>${registrationOtp}</strong>. It expires in 15 minutes.</p>`
      },
      { headers: { 'api-key': process.env.BREVO_API_KEY, 'Content-Type': 'application/json' }, timeout: 15000 }
    );

    return res.status(200).json({ success: true, message: "Verification OTP code sent to your email." });
  } catch (err) {
    console.error("❌ Registration Entry Initialization Crash:", err.message);
    return res.status(500).json({ error: "Failed to process registration entry.", details: err.message });
  }
});


app.post('/api/register/verify', async (req, res) => {
  try {
    const { email, otp, bvn } = req.body;
    if (!email || !otp || !bvn) {
      return res.status(400).json({ error: "Email, OTP code, and BVN are required." });
    }

    const normalizedEmail = email.toLowerCase().trim();
    const user = await User.findOne({ email: normalizedEmail });
    if (!user) return res.status(400).json({ error: "Registration session not found." });
    if (user.isVerified) return res.status(400).json({ error: "Account is already verified." });
    if (!user.otpCode) return res.status(400).json({ error: "Session data missing. Restart." });
    if (user.otpCode !== otp.toString().trim()) return res.status(400).json({ error: "Invalid code." });
    if (Date.now() > user.otpExpires) return res.status(400).json({ error: "Code expired. Restart." });

    // Format clean string names to pass live API validation rules safely
    const nameParts = (user.name || "User VaultPay").split(" ");
    const firstName = nameParts[0] || "User";
    const lastName = nameParts.slice(1).join(" ") || "VaultPay";
    const cleanPhone = (user.phone || '08012345678').replace(/\D/g, '');

    console.log(`📡 Sending Live Request to Flutterwave for: ${normalizedEmail}`);

    // Call Flutterwave's live Virtual Account provision route
    const flwResponse = await axios.post(
      'https://api.flutterwave.com/v3/virtual-account-numbers',
      {
        email: normalizedEmail,
        is_permanent: true,
        bvn: bvn.toString().trim(), // Type '12345678901' on your phone to pass sandbox checks successfully!
        tx_ref: `VP-REF-${Date.now()}`,
        firstname: firstName,
        lastname: lastName,
        phonenumber: cleanPhone
      },
      { 
        headers: { 
          Authorization: `Bearer ${process.env.FLW_SECRET_KEY}`, 
          'Content-Type': 'application/json' 
        }, 
        timeout: 20000 
      }
    );

    // If Flutterwave rejects the request payload parameters, catch it instantly here
    if (!flwResponse.data || flwResponse.data.status !== 'success') {
      return res.status(400).json({ 
        error: "Flutterwave routing allocation failed.", 
        details: flwResponse.data?.message || "Unknown error context."
      });
    }

    const flwData = flwResponse.data.data;
    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "7d" });

    // Commit live structural data payload fields to MongoDB safely
    user.isVerified = true;
    user.account_number = flwData.account_number;
    user.bank_name = flwData.bank_name; 
    user.account_name = flwData.account_name;
    user.otpCode = undefined;
    user.otpExpires = undefined;
    user.wallet_balance = 0.00; // Fresh production standard live balance initialization
    await user.save();

    return res.status(200).json({
      success: true,
      message: "Account active!",
      token,
      hasPin: false,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        wallet_balance: user.wallet_balance,
        account_info: {
          account_number: user.account_number,
          bank_name: user.bank_name,
          holder_name: user.account_name
        }
      }
    });

  } catch (err) {
    // Captures precise stack response data details directly from Flutterwave servers if it drops
    const errorMsg = err.response?.data?.message || err.message;
    console.error("❌ Live Integration Error:", errorMsg);
    return res.status(500).json({ 
      error: "Verification failed on remote validation layer.", 
      details: errorMsg 
    });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required." });
    }

    const normalizedEmail = email.toLowerCase().trim();
    const user = await User.findOne({ email: normalizedEmail });
    if (!user) return res.status(400).json({ error: "Invalid credentials." });
    if (!user.isVerified) return res.status(400).json({ error: "Please verify your email first." });

        const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: "Invalid credentials." });

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "7d" });

    return res.status(200).json({
      success: true,
      token,
      hasPin: user.transactionPin ? true : false,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        wallet_balance: user.wallet_balance
      }
    });
  } catch (err) {
    return res.status(500).json({ error: "Login failed.", details: err.message });
  }
});
app.post('/api/profile/set-pin', auth, async (req, res) => {
  try {
    const { pin } = req.body;
    if (!pin || pin.length !== 4 || isNaN(pin)) {
      return res.status(400).json({ error: "PIN must be a 4-digit number." });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPin = await bcrypt.hash(pin.toString(), salt);

    await User.findByIdAndUpdate(req.user.id, { transactionPin: hashedPin });

    return res.status(200).json({ success: true, message: "Transaction PIN set successfully." });
  } catch (err) {
    return res.status(500).json({ error: "Failed to set PIN.", details: err.message });
  }
});

app.get('/api/profile/me', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password -transactionPin -otpCode -resetOtpCode');
    if (!user) return res.status(404).json({ error: "User not found." });

    return res.status(200).json({ success: true, user });
  } catch (err) {
    return res.status(500).json({ error: "Failed to fetch profile.", details: err.message });
  }
});


app.post('/api/webhook/flutterwave', async (req, res) => {
  try {
    const secretHash = process.env.FLW_WEBHOOK_HASH;
    const signature = req.headers["verif-hash"];
    
    if (signature !== secretHash) {
      return res.status(401).json({ error: "Invalid signature" });
    }

    const { event, data } = req.body;
    console.log("🔔 Incoming Webhook Event:", event);

        if (event === "virtual_account.credit") {
      const { account_number, amount, tx_ref, flw_ref } = data;
      const depositAmount = Number(amount);

      const user = await User.findOne({ account_number: account_number });
      if (user) {
        user.wallet_balance += depositAmount;
        await user.save();

        await Transaction.create({
          user_id: user._id,
          type: "Deposit",
          amount: depositAmount,
          description: `Virtual Account Deposit`,
          reference: tx_ref || flw_ref || `DEP-${Date.now()}`,
          status: "SUCCESSFUL"
        });

        console.log(`💰 Credited ${depositAmount} to account ${account_number}`);
      }
    }
    
    return res.status(200).json({ status: "success" });
  } catch (err) {
    console.error("❌ Webhook Error:", err.message);
    return res.status(500).json({ error: "Webhook internal failure" });
  }
});


app.get('/api/transactions/history', auth, async (req, res) => {
  try {
    const history = await Transaction.find({ user_id: req.user.id })
      .sort({ created_at: -1 });

    return res.status(200).json({ success: true, transactions: history });
  } catch (err) {
    return res.status(500).json({ error: "Failed to fetch history.", details: err.message });
  }
});


//verify account number

app.post('/api/transfer/verify-account', auth, async (req, res) => {
  try {
    const { account_number, account_bank } = req.body;
    if (!account_number || !account_bank) {
      return res.status(400).json({ error: "Account number and bank code are required." });
    }

    const flwResponse = await axios.post(
      'https://api.flutterwave.com/v3/accounts/resolve',
      { account_number, account_bank },
      { headers: { Authorization: `Bearer ${process.env.FLW_SECRET_KEY}`, 'Content-Type': 'application/json' } }
    );

    return res.status(200).json({ success: true, data: flwResponse.data.data });
  } catch (err) {
    const errorMsg = err.response?.data?.message || err.message;
    return res.status(400).json({ error: "Could not verify account name.", details: errorMsg });
  }
});


//bank transfer

app.post('/api/transfer/send', auth, async (req, res) => {
  try {
    const { amount, bank_code, account_number, account_name, pin, description } = req.body;
    if (!amount || !bank_code || !account_number || !pin) {
      return res.status(400).json({ error: "Missing required transfer fields." });
    }

    const user = await User.findById(req.user.id);
    if (!user.transactionPin) return res.status(400).json({ error: "Please set up a transaction PIN first." });

    const isPinCorrect = await bcrypt.compare(pin.toString(), user.transactionPin);
    if (!isPinCorrect) return res.status(400).json({ error: "Incorrect transaction PIN." });

    const transferAmount = Number(amount);
    if (user.wallet_balance < transferAmount) return res.status(400).json({ error: "Insufficient wallet balance." });

    //process bank transfer

        const uniqueRef = `VP-TX-${Date.now()}-${Math.floor(1000 + Math.random() * 9000)}`;
    
    user.wallet_balance -= transferAmount;
    await user.save();

    const flwResponse = await axios.post(
      'https://api.flutterwave.com/v3/transfers',
      {
        account_bank: bank_code,
        account_number: account_number,
        amount: transferAmount,
        narrative: description || "VaultPay Transfer",
        currency: "NGN",
        reference: uniqueRef,
        callback_url: 'https://vaultpay-backend-883s.onrender.com'
      },
      { headers: { Authorization: `Bearer ${process.env.FLW_SECRET_KEY}`, 'Content-Type': 'application/json' }, timeout: 18000 }
    );
    await Transaction.create({
      user_id: user._id,
      type: "Bank Transfer",
      amount: transferAmount,
      description: description || "VaultPay Bank Transfer",
      recipient_account: account_number,
      recipient_bank: bank_code,
      reference: uniqueRef,
      status: "PENDING"
    });

    return res.status(200).json({
      success: true,
      message: "Transfer initiated successfully.",
      reference: uniqueRef
    });
  } catch (err) {
    const errorMsg = err.response?.data?.message || err.message;
    return res.status(500).json({ error: "Transfer processing failed.", details: errorMsg });
  }
});

app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "Email is required." });

    const normalizedEmail = email.toLowerCase().trim();
    const user = await User.findOne({ email: normalizedEmail });
    if (!user) return res.status(400).json({ error: "User with this email does not exist." });

    const resetOtp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiryTime = Date.now() + 15 * 60 * 1000;

    user.resetOtpCode = resetOtp;
    user.resetOtpExpires = expiryTime;
    await user.save();

    await axios.post(
      'https://api.brevo.com/v3/smtp/email',
      {
        sender: { name: "VaultPay Security", email: "ichinegbo@gmail.com" },
        to: [{ email: normalizedEmail }],
        subject: "Reset Your VaultPay Password",
        htmlContent: `<p>Hello,</p><p>You requested a password reset. Your verification code is: <strong>${resetOtp}</strong>. It expires in 15 minutes.</p>`
      },
      { headers: { 'api-key': process.env.BREVO_API_KEY, 'Content-Type': 'application/json' }, timeout: 15000 }
    );

    return res.status(200).json({ success: true, message: "Password reset OTP sent to email." });
  } catch (err) {
    return res.status(500).json({ error: "Failed to process forgot password.", details: err.message });
  }
});

app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;
    if (!email || !otp || !newPassword) {
      return res.status(400).json({ error: "All fields are required." });
    }

    const normalizedEmail = email.toLowerCase().trim();
    const user = await User.findOne({ email: normalizedEmail });
    if (!user) return res.status(400).json({ error: "User not found." });

    if (!user.resetOtpCode || user.resetOtpCode !== otp.toString().trim()) {
      return res.status(400).json({ error: "Invalid reset code." });
    }
    if (Date.now() > user.resetOtpExpires) {
      return res.status(400).json({ error: "Reset code has expired." });
    }

    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(newPassword, salt);
    
    user.resetOtpCode = undefined;
    user.resetOtpExpires = undefined;
    await user.save();

    return res.status(200).json({ success: true, message: "Password reset successful. You can now log in." });
  } catch (err) {
    return res.status(500).json({ error: "Failed to reset password.", details: err.message });
  }
});

// GET ALL NIGERIAN BANKS
app.get('/api/banks', async (req, res) => {
  try {
    const flwResponse = await axios.get(
      'https://api.flutterwave.com/v3/banks/NG',
      { 
        headers: { Authorization: `Bearer ${process.env.FLW_SECRET_KEY}` },
        timeout: 10000
      }
    );

    if (flwResponse.data.status !== 'success') {
      return res.status(400).json({ error: "Could not fetch banks" });
    }

    // Clean the data: only send what Flutter needs
    const banks = flwResponse.data.data.map(bank => ({
      name: bank.name,
      code: bank.code
    }));

    return res.status(200).json({ success: true, banks });
  } catch (err) {
    const errorMsg = err.response?.data?.message || err.message;
    return res.status(500).json({ error: "Failed to fetch banks", details: errorMsg });
  }
});

app.get('/api/bills/data-bundles', auth, async (req, res) => {
  try {
    const { operator } = req.query; // Expects 'MTN', 'GLO', 'AIRTEL', or '9MOBILE'
    if (!operator) {
      return res.status(400).json({ error: "Telecom operator parameter is required." });
    }

    const cleanOperator = operator.toUpperCase().trim();
    const isTestMode = process.env.FLW_SECRET_KEY && process.env.FLW_SECRET_KEY.startsWith("FLWSECK_TEST");

    // 🛡️ FALLBACK ENVIRONMENT RULE: Serve clean local mock plans if calling test keys
    if (isTestMode) {
      console.log(`🛠️ Serving Automated Sandbox Bundles for operator: ${cleanOperator}`);
      
      const mockPackages = [
        { biller_code: "BIL108", item_code: "MD1", name: `${cleanOperator} 1GB - 1 DAY (DAILY FLAT)`, price: 350.0 },
        { biller_code: "BIL108", item_code: "MD2", name: `${cleanOperator} 2.5GB - 2 DAYS (PRO VALUE)`, price: 600.0 },
        { biller_code: "BIL108", item_code: "MD3", name: `${cleanOperator} 5GB - 7 DAYS (WEEKLY PASS)`, price: 1500.0 },
        { biller_code: "BIL108", item_code: "MD4", name: `${cleanOperator} 10GB - 30 DAYS (MONTHLY BASIC)`, price: 3000.0 },
        { biller_code: "BIL108", item_code: "MD5", name: `${cleanOperator} 25GB - 30 DAYS (MONTHLY PRO)`, price: 6500.0 }
      ];
      
      return res.status(200).json({ success: true, bundles: mockPackages });
    }

    // 📡 PRODUCTION ENVIRONMENT RULE: Hits Flutterwave live server database automatically
    console.log(`📡 Fetching Live Flutterwave Catalog for operator: ${cleanOperator}`);
    const response = await axios.get(
      'https://api.flutterwave.com/v3/bills',
      {
        headers: { 
          Authorization: `Bearer ${process.env.FLW_SECRET_KEY}`,
          'Content-Type': 'application/json'
        },
        timeout: 20000
      }
    );

    if (response.data && response.data.status === 'success') {
      const allBundles = response.data.data;
      
      const filteredBundles = allBundles.filter(item => {
        const name = item.biller_name.toUpperCase();
        const matchesOperator = name.includes(cleanOperator) || (cleanOperator === '9MOBILE' && name.includes('0903'));
        const isDataProduct = name.includes("DATA") || name.includes("BUNDLE") || name.includes("INTERNET");
        return matchesOperator && isDataProduct;
      }).map(item => ({
        biller_code: item.biller_code,
        item_code: item.item_code,
        name: item.name.toUpperCase(),
        price: item.amount,
      }));

      return res.status(200).json({ success: true, bundles: filteredBundles });
    } else {
      return res.status(400).json({ error: "Could not retrieve live packages from gateway provider." });
    }

  } catch (err) {
    console.error("❌ Data Bundles Endpoint Exception:", err.message);
    return res.status(500).json({ error: "Failed to load dynamic data packages." });
  }
});


app.post('/api/bills/send', auth, async (req, res) => {
  try {
    const { type, amount, phone_number, operator, pin, description, biller_code, item_code } = req.body;
    
    // 1. Core Request Payload Validation
    if (!type || !amount || !phone_number || !operator || !pin) {
      return res.status(400).json({ error: "Missing required checkout parameters." });
    }

    const parsedAmount = parseFloat(amount);
    if (isNaN(parsedAmount) || parsedAmount <= 0) {
      return res.status(400).json({ error: "Invalid transaction amount valuation." });
    }

    // 2. Locate User Profile and Validate PIN
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: "User session context missing." });
    
    if (!user.transactionPin) {
      return res.status(400).json({ error: "Please configure a secure transaction PIN first." });
    }

    const isPinMatch = await bcrypt.compare(pin.toString(), user.transactionPin);
    if (!isPinMatch) return res.status(400).json({ error: "Incorrect security transaction PIN code." });

    // 3. Balance Sufficiency Ledger Checks
    if (user.wallet_balance < parsedAmount) {
      return res.status(400).json({ error: "Insufficient account balance to authorize payment." });
    }

    const referenceId = `VP-TX-${type.toUpperCase().substring(0, 3)}-${Date.now()}`;
    const isTestMode = process.env.FLW_SECRET_KEY && process.env.FLW_SECRET_KEY.startsWith("FLWSECK_TEST");

    // 🛡️ DYNAMIC RUNTIME ROUTING ENVIRONMENT CHECK
    if (!isTestMode) {
      console.log(`📡 Dispatched Live Bills Payment API Route request to Flutterwave for: ${phone_number}`);
      try {
        // Formulates Flutterwave production standard payload map configurations
        await axios.post(
          'https://api.flutterwave.com/v3/bills',
          {
            country: "NG",
            customer: phone_number.toString(),
            amount: parsedAmount,
            type: type.toUpperCase() === 'DATA' ? item_code : `${operator.toUpperCase()}_AIRTIME`,
            reference: referenceId
          },
          { headers: { Authorization: `Bearer ${process.env.FLW_SECRET_KEY}`, 'Content-Type': 'application/json' } }
        );
      } catch (flwErr) {
        const remoteMsg = flwErr.response?.data?.message || flwErr.message;
        console.error("❌ Live Billing Provider Decline Trace:", remoteMsg);
        return res.status(400).json({ error: "Utility provider declined checkout transaction processing.", details: remoteMsg });
      }
    } else {
      console.log(`🛠️ Simulated Sandbox Ledger Validation Successful for ${type}: ${phone_number}`);
    }

    // 4. Update Database Account Balances and Log Ledger Record
    user.wallet_balance -= parsedAmount;
    await user.save();

    await Transaction.create({
      user_id: user._id,
      type: type, // 'Airtime' or 'Data'
      amount: parsedAmount,
      description: description || `${operator.toUpperCase()} ${type.toUpperCase()} PAYMENT`,
      recipient_account: phone_number,
      recipient_bank: operator.toUpperCase(),
      reference: referenceId,
      status: 'SUCCESSFUL'
    });

    return res.status(200).json({
      success: true,
      message: `${type.toUpperCase()} TRANSACTION AUTHORIZED SUCCESSFULLY`,
      new_balance: user.wallet_balance
    });

  } catch (err) {
    console.error("❌ Utility Checkout Endpoint Execution Exception:", err.message);
    return res.status(500).json({ error: "Failed to process utility purchase execution handler." });
  }
});



const PORT = process.env.PORT || 10000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 VaultPay Server running globally on port ${PORT}`);
});