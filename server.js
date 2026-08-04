const nodemailer = require('nodemailer');
const express = require('express');
const mongoose = require('mongoose');
require('dotenv').config();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const axios = require('axios');
const cors = require('cors'); // Moved to the top for consistency

const app = express();
app.use(cors());
const JWT_SECRET = process.env.JWT_SECRET;
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

// AUTH MIDDLEWARE (FIXED)
const auth = async (req, res, next) => {
  try {
    const token = req.header('Authorization');
    if (!token) return res.status(401).json({ error: "No token, access denied" });

    const decoded = jwt.verify(token.replace('Bearer ', ''), process.env.JWT_SECRET);
    
    // FIX: Set req.user as an object so that req.user.id works across all routes
    req.user = { id: decoded.id }; 
    next();
  } catch (err) {
    res.status(401).json({ error: "Token is not valid" });
  }
};
app.post('/api/webhook/flutterwave', async (req, res) => {
  const secretHash = process.env.FLW_WEBHOOK_HASH;
  const signature = req.headers["verif-hash"];
  
  if (signature!== secretHash) {
    return res.status(401).json({ error: "Invalid signature" });
  }

  const event = req.body;
  console.log("Webhook event:", event.event);

  if (event.event === "virtual_account.credit") {
    const { account_number, amount, transaction_id } = event.data;
    // credit user wallet here
  }
  
  res.status(200).json({ status: "success" });
});
// STEP 1: VALIDATE DATA AND SEND OTP EMAIL
app.post('/api/register/initiate', async (req, res) => {
  try {
    const { name, email, phone, password, bvn } = req.body;
    if (!name ||!email ||!phone ||!password ||!bvn) {
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

// STEP 2: VERIFY CODE, RUN FLUTTERWAVE PIPELINE, AND ACTIVATE ACCOUNT - FIXED
app.post('/api/register/verify', async (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!email ||!otp) return res.status(400).json({ error: "Email and OTP code are required." });

    const normalizedEmail = email.toLowerCase().trim();
    const user = await User.findOne({ email: normalizedEmail });
    if (!user) return res.status(400).json({ error: "Registration session not found." });
    if (user.isVerified) return res.status(400).json({ error: "Account is already verified." });
    if (!user.otpCode) return res.status(400).json({ error: "Verification session data missing. Restart registration." });
    if (user.account_number) return res.status(400).json({ error: "Account already has bank details." }); // PREVENT DUPLICATE KEY

    const parts = user.otpCode.split('-');
    const savedOtp = parts[0];
    const cleanBvn = parts[1];

    if (savedOtp!== otp.toString().trim()) return res.status(400).json({ error: "Invalid verification code." });
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

    if (flwResponse.data.status!== 'success') {
      return res.status(400).json({ error: "Fintech routing allocation failed. Check BVN metrics.", details: flwResponse.data.message });
    }

    const flwData = flwResponse.data;

    // CREATE TOKEN HERE - THIS WAS MISSING
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
      token: token, // FIXED
      user: { // FIXED: removed extra comma
        id: user._id,
        account_info: {
          account_number: user.account_number,
          bank_name: flwData.bank_name,
          holder_name: user.name
        }
      }
    });

  } catch (err) {
    const errorMsg = err.response?.data?.message || err.message;
    console.error("❌ Final Verification/Fintech Error:", errorMsg);
    return res.status(500).json({ error: "Verification processing failed.", details: errorMsg });
  }
});

// LOGIN
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: "User not found" });
    
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: "Wrong password" });
    
    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: "7d" });
    
    const { password: _, ...userWithoutPassword } = user.toObject();
    res.json({ message: "Login successful", token, user: userWithoutPassword });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// SET TRANSACTION PIN
app.post('/set-pin', auth, async (req, res) => {
  try {
    const { pin } = req.body;
    const userId = req.user.id;

    if (!pin || pin.length !== 4 || isNaN(pin)) {
      return res.status(400).json({ error: "PIN must be 4 digits" });
    }

    const hashedPin = await bcrypt.hash(pin, 10);
    await User.findByIdAndUpdate(userId, { transactionPin: hashedPin });

    res.json({ message: "Transaction PIN set successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// BALANCE
app.get('/balance', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: "User not found" });
    
    res.json({ 
      name: user.name,
      account_number: user.account_number,
      balance: user.wallet_balance 
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET USER TRANSACTION HISTORY WITH PAGINATION AND LIMITS
app.get('/transactions', auth, async (req, res) => {
  try {
    // 1. Get query parameters from the URL (defaults: page 1, limit 10)
    // Example: /transactions?limit=5 will load only 5 items
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    // 2. Fetch the paginated records from MongoDB
    const history = await Transaction.find({ userId: req.user.id })
      .sort({ date: -1 }) // Newest first
      .skip(skip)         // Skip items from previous pages
      .limit(limit);      // Limit the number of items returned

    // 3. Count total transactions for this user (useful for frontend pagination UI)
    const totalTransactions = await Transaction.countDocuments({ userId: req.user.id });

    // 4. Return clear structural data back to the frontend
    res.json({
      success: true,
      currentPage: page,
      totalPages: Math.ceil(totalTransactions / limit),
      totalItems: totalTransactions,
      count: history.length,
      transactions: history
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// TRANSFER TO REAL BANK ACCOUNTS VIA FLUTTERWAVE
app.post('/send', auth, async (req, res) => {
  try {
    const { account_number, bank_code, amount, pin, description } = req.body;

    // 1. Basic validation
    if (!account_number || !bank_code || !amount || !pin) {
      return res.status(400).json({ error: "Missing required transfer fields" });
    }
    if (amount <= 0) {
      return res.status(400).json({ error: "Amount must be greater than 0" });
    }

    // 2. Fetch the sender inside your system
    const sender = await User.findById(req.user.id);
    if (!sender) {
      return res.status(404).json({ error: "Sender profile not found" });
    }

    // 3. Verify sender's security PIN
    const isPinValid = await bcrypt.compare(pin, sender.transactionPin);
    if (!isPinValid) {
      return res.status(400).json({ error: "Invalid transaction PIN" });
    }

    // 4. Verify sender has enough funds inside your app balance
    if (sender.wallet_balance < amount) {
      return res.status(400).json({ error: "Insufficient wallet balance" });
    }

    // 5. Generate a unique transaction reference for tracking
    const uniqueReference = `VTP_TX_${Date.now()}_${Math.floor(Math.random() * 1000)}`;

    // 6. Build the payload for the Flutterwave Payout API Engine
    const flutterwavePayload = {
      account_bank: bank_code,
      account_number: account_number,
      amount: Number(amount),
      narration: description || "VaultPay Transfer",
      currency: "NGN",
      reference: uniqueReference,
      callback_url: "https://your-render-app.onrender.com/webhook/flutterwave" // Adjust as needed
    };

    // 7. Make the live API Call to Flutterwave to execute the transfer
    const response = await axios.post(
       'https://api.flutterwave.com/v3/transfers',
      flutterwavePayload,
      {
        headers: { Authorization: `Bearer ${process.env.FLW_SECRET_KEY}` }
      }
    );

    // 8. Deduct the funds from the user's wallet balance if API call is successful
    sender.wallet_balance -= amount;
    await sender.save();

    // 9. Save log details to your MongoDB transaction collection
    const newTransaction = new Transaction({
      userId: sender._id,
      type: 'debit',
      amount: amount,
      description: description || "Bank Transfer",
      reference: uniqueReference,
      status: response.data.status === "success" ? 'successful' : 'pending',
      recipient: `${account_number} (${bank_code})`
    });
    await newTransaction.save();

    // 10. Return final updated data back to your frontend
    res.json({
      message: "Transfer initiated successfully",
      newBalance: sender.wallet_balance,
      transferDetails: response.data.data
    });

  } catch (err) {
    // Graceful error logging to catch invalid bank details or upstream server issues
    const errorMessage = err.response?.data?.message || err.message;
    res.status(500).json({ error: `Transfer failed: ${errorMessage}` });
  }
});

// DEPOSIT
app.post('/deposit', auth, async (req, res) => {
  try {
    const { amount } = req.body;
    const user = await User.findById(req.user.id);

    if (amount <= 0) return res.status(400).json({ error: "Amount must be greater than 0" });

    const tx_ref = `VTP_FUND_${Date.now()}`;

    const payload = {
      tx_ref: tx_ref,
      amount: amount,
      currency: "NGN",
      redirect_url: "https://swiftpay-backend-v2.onrender.com/payment-success",
      customer: {
        email: user.email,
        name: user.name
      },
      meta: {
        userId: user._id.toString()
      },
      customizations: {
        title: "VaultPay Wallet Funding",
        description: `Fund wallet with ${amount}`
      }
    };

    const response = await axios.post(
      'https://api.flutterwave.com/v3/payments',
      payload,
      { headers: { Authorization: `Bearer ${process.env.FLW_SECRET_KEY}` } }
    );

    res.status(200).json({ 
      message: 'Payment link created',
      payment_link: response.data.data.link 
    });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// WITHDRAW
app.post('/withdraw', auth, async (req, res) => {
  try {
    const { amount } = req.body;
    const user = await User.findById(req.user.id);

    if (amount <= 0) return res.status(400).json({ error: "Amount must be greater than 0" });
    if (user.wallet_balance < amount) return res.status(400).json({ error: "Insufficient funds" });

    user.wallet_balance -= amount;
    await user.save();

    res.json({
      message: `Withdrew ₦${amount} successfully`,
      newBalance: user.wallet_balance
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const FLW_SECRET_KEY = process.env.FLW_SECRET_KEY;

// GET ALL BANKS
app.get('/banks', async (req, res) => {
  try {
    const response = await axios.get('https://api.flutterwave.com/v3/banks/NG', {
      headers: { Authorization: `Bearer ${FLW_SECRET_KEY}` }
    });
    res.json(response.data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// VERIFY ACCOUNT NAME (FIXED API TARGET URL)
app.post('/verify-account', auth, async (req, res) => {
  try {
    const { account_number, bank_code } = req.body;

    if (!account_number || !bank_code) {
      return res.status(400).json({ error: "account_number and bank_code are required" });
    }

    // THE FIXED API URL: Points strictly to the official API routing infrastructure
    const targetUrl = 'https://api.flutterwave.com/v3/accounts/resolve';

    const response = await axios.post(targetUrl, {
      account_number: account_number,
      account_bank: bank_code
    }, {
      headers: { 
        'Authorization': `Bearer ${process.env.FLW_SECRET_KEY}`,
        'Content-Type': 'application/json'
      }
    });
    
    // Transmits the resolved name dictionary back to your mobile screen structure
    res.json(response.data);

  } catch (err) {
    // Keeps you updated on incoming server responses inside your terminal
    console.error("❌ Name Verification Backend Error:", err.response?.data || err.message);
    
    res.status(500).json({ 
      error: "Verification failed", 
      details: err.response?.data?.message || err.message 
    });
  }
});

// GET CURRENT LOGGED-IN USER PROFILE
app.get('/profile', auth, async (req, res) => {
  try {
    // 1. Fetch user data using the ID extracted by the auth middleware
    // 2. select('-password') ensures the hashed password is NEVER exposed to the frontend
    const user = await User.findById(req.user.id).select('-password');
    
    if (!user) {
      return res.status(404).json({ error: "User profile not found" });
    }

    // 3. Return clean user details back to your app
    res.json({
      success: true,
      user: user
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
// CHANGE PASSWORD ROUTE
app.post('/change-password', auth, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;

    // 1. Basic input validation
    if (!oldPassword || !newPassword) {
      return res.status(400).json({ error: "Both old and new passwords are required" });
    }
    if (newPassword.length < 6) {
      return res.status(400).json({ error: "New password must be at least 6 characters long" });
    }

    // 2. Fetch the user with their password from the database
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // 3. Verify that the old password matches what is in the database
    const isMatch = await bcrypt.compare(oldPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: "Incorrect current password" });
    }

    // 4. Hash the new password and update the user document
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(newPassword, salt);
    await user.save();

    res.json({ success: true, message: "Password updated successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
// 1. FETCH AVAILABLE BILLS CATEGORIES - PUBLIC
app.get('/api/bills/categories', async (req, res) => {
  try {
    const { type } = req.query;
    const url = type 
     ? `https://api.flutterwave.com/v3/bill-categories?type=${type}&country=NG` 
      : 'https://api.flutterwave.com/v3/bill-categories?country=NG';

    const response = await axios.get(url, {
      headers: { Authorization: `Bearer ${process.env.FLW_SECRET_KEY}` }
    });
    res.json({ success: true, data: response.data || [] });
  } catch (err) {
    console.log("FLW CATEGORIES ERROR:", err.response?.data);
    res.status(500).json({ success: false, error: err.response?.data?.message || err.message });
  }
});

// 2. FETCH BILL ITEMS / PACKAGES - PUBLIC
app.get('/api/bills/items', async (req, res) => {
  try {
    const { item_code } = req.query;
    if (!item_code) return res.status(400).json({ error: "item_code is required" });

    const response = await axios.get(
      `https://api.flutterwave.com/v3/bills/categories/${item_code}/products`,
      { headers: { Authorization: `Bearer ${process.env.FLW_SECRET_KEY}` } }
    );
    res.json({ success: true, items: response.data || [] });
  } catch (err) {
    console.log("BILL ITEMS ERROR", err.response?.data || err.message);
    res.status(500).json({ error: err.response?.data || err.message });
  }
});

// 3. VALIDATE CUSTOMER BILL DETAILS - PUBLIC
app.post('/api/bills/validate', async (req, res) => {
  try {
    const { item_code, code, customer } = req.body;
    if (!item_code || !code || !customer) {
      return res.status(400).json({ error: "item_code, code, and customer are required" });
    }

    const response = await axios.get(
      `https://api.flutterwave.com/v3/bill-validation/${item_code}/validate?code=${code}&customer=${customer}`,
      { headers: { Authorization: `Bearer ${process.env.FLW_SECRET_KEY}` } }
    );
    res.json({ success: true, customerDetails: response.data.data });
  } catch (err) {
    console.log("VALIDATE ERROR:", err.response?.data)
    res.status(500).json({ error: `Validation failed: ${err.response?.data?.message || err.message}` });
  }
});
// ===== HELPER: DEDUCT + LOG + CALL FLW BILL =====
async function payBill({ userId, amount, type, description, flwPayload }) {
  const user = await User.findById(userId);
  if (!user) throw new Error("User profile not found");
  if (user.wallet_balance < amount) throw new Error("Insufficient wallet balance");

  const uniqueReference = `VTP_BILL_${Date.now()}_${Math.floor(Math.random() * 1000)}`;
  
  // 1. DEDUCT FIRST
  user.wallet_balance -= amount;
  await user.save();

  try {
    // 2. PAY FLUTTERWAVE
    const response = await axios.post(
      'https://api.flutterwave.com/v3/bills',
      { ...flwPayload, reference: uniqueReference, recurrence: "ONCE" },
      { headers: { Authorization: `Bearer ${process.env.FLW_SECRET_KEY}` } }
    );

    if (response.data.status !== "success") {
      user.wallet_balance += amount; // REFUND
      await user.save();
      throw new Error(response.data.message);
    }

    // 3. LOG TRANSACTION
    const newTransaction = new Transaction({
      userId: user._id,
      type: 'debit',
      amount: amount,
      description: description,
      reference: uniqueReference,
      status: 'successful',
      recipient: flwPayload.customer
    });
    await newTransaction.save();

    return { newBalance: user.wallet_balance, billDetails: response.data }
  } catch (err) {
    user.wallet_balance += amount; // REFUND
    await user.save();
    throw err;
  }
}

// ====================================================================
// FIXED LIVE BILLER SYSTEM: AIRTIME, DATA, AND CATEGORIES
// ====================================================================

/**
 * Helper function to handle wallet balance and call Flutterwave API
 */
async function payBill({ userId, amount, description, flwPayload }) {
  const user = await User.findById(userId);
  if (!user) throw new Error("User not found");
  if (user.wallet_balance < Number(amount)) throw new Error("Insufficient wallet balance");

  const tx_ref = `VP-BILL-${Date.now()}`;
  
  // Call Flutterwave live endpoint
  const flwResponse = await axios.post(
    'https://flutterwave.com',
    { ...flwPayload, reference: tx_ref },
    { headers: { Authorization: `Bearer ${process.env.FLW_SECRET_KEY}`, 'Content-Type': 'application/json' } }
  );

  if (flwResponse.data.status !== 'success') {
    throw new Error(flwResponse.data.message || "Biller processor failed payment assignment.");
  }

  // Deduct Wallet
  user.wallet_balance -= Number(amount);
  await user.save();

  // Save transaction to database log tracking records
  const transaction = new Transaction({
    userId: user._id,
    type: 'debit',
    amount: Number(amount),
    description: description,
    reference: tx_ref,
    status: 'successful',
    recipient: flwPayload.customer
  });
  await transaction.save();

  return { balance: user.wallet_balance, tx: transaction };
}

/**
 *   GET /api/biller/categories
 * rovides filtered biller categories to populate the dropdown
 */
app.get('/api/biller/categories', auth, async (req, res) => {
  try {
    const { type } = req.query; // Captures 'airtime' or 'data_bundle' from Flutter frontend query params
    
    const response = await axios.get('https://api.flutterwave.com/v3/billers', {
      headers: { Authorization: `Bearer ${process.env.FLW_SECRET_KEY}` }
    });

    let rawData = response.data.data || [];

    // Filter categories explicitly so the dropdown payload size is manageable
    if (type === 'airtime') {
      rawData = rawData.filter(item => item.category.toLowerCase() === 'airtime');
    } else if (type === 'data_bundle') {
      rawData = rawData.filter(item => item.category.toLowerCase() === 'data bundle');
    }

    return res.status(200).json({ success: true, data: rawData });
  } catch (err) {
    console.error("❌ Dropdown categories collection failed:", err.response?.data || err.message);
    return res.status(500).json({ error: "Failed to fetch live biller dropdown options." });
  }
});

/**
 * @route   POST /api/biller/airtime
 * @desc    Processes airtime topups using proper URL matching
 */
app.post('/api/biller/airtime', auth, async (req, res) => {
  try {
    const { country, customer, amount, item_code, code, pin } = req.body;
    if (!pin) return res.status(400).json({ error: "Transaction PIN required" });

    const user = await User.findById(req.user.id);
    if (!user.transactionPin) return res.status(400).json({ error: "Transaction PIN is not configured." });

    const isPinValid = await bcrypt.compare(pin, user.transactionPin);
    if (!isPinValid) return res.status(400).json({ error: "Invalid transaction PIN" });

    // FIX: type parameter must be the specific biller code identifier (e.g., 'BIL108') passed from Flutter
    const result = await payBill({
      userId: req.user.id, 
      amount, 
      description: `Airtime purchase for mobile line: ${customer}`,
      flwPayload: { country: country || "NG", customer, amount: Number(amount), type: code, item_code }
    });

    return res.json({ success: true, message: "Airtime sent successfully", ...result });
  } catch (err) {
    console.error("❌ Airtime route failure:", err.message);
    return res.status(500).json({ error: err.message });
  }
});

/**
 * @route   POST /api/biller/data
 * @desc    Processes mobile data package purchases
 */
app.post('/api/biller/data', auth, async (req, res) => {
  try {
    const { country, customer, amount, item_code, code, pin } = req.body;
    if (!pin) return res.status(400).json({ error: "Transaction PIN required" });

    const user = await User.findById(req.user.id);
    if (!user.transactionPin) return res.status(400).json({ error: "Transaction PIN is not configured." });

    const isPinValid = await bcrypt.compare(pin, user.transactionPin);
    if (!isPinValid) return res.status(400).json({ error: "Invalid transaction PIN" });

    // FIX: passed correct bundle structural tracking codes mapping schemas
    const result = await payBill({
      userId: req.user.id, 
      amount, 
      description: `Data Bundle purchase for mobile line: ${customer}`,
      flwPayload: { country: country || "NG", customer, amount: Number(amount), type: code, item_code }
    });

    return res.json({ success: true, message: "Data bundle sent successfully", ...result });
  } catch (err) {
    console.error("❌ Data route failure:", err.message);
    return res.status(500).json({ error: err.message });
  }
});

// ===== GROUP 2: BILLS - ELECTRICITY + CABLE =====
app.post('/api/bills/electricity',auth, async (req, res) => {
  try {
    const { country, customer, amount, item_code, code, pin } = req.body; // customer = meter no
    if (!pin) return res.status(400).json({ error: "Transaction PIN required" });
    const user = await User.findById(req.user.id);
    const isPinValid = await bcrypt.compare(pin, user.transactionPin);
    if (!isPinValid) return res.status(400).json({ error: "Invalid transaction PIN" });

    const result = await payBill({
      userId: req.user.id, amount, type: "ELECTRICITY",
      description: `Electricity: ${customer}`,
      flwPayload: { country: "NG", customer, amount, type: "ELECTRICITY", item_code, code }
    });
    res.json({ success: true, message: "Electricity token sent", ...result });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/bills/cable',auth, async (req, res) => {
  try {
    const { country, customer, amount, item_code, code, pin } = req.body; // customer = smartcard
    if (!pin) return res.status(400).json({ error: "Transaction PIN required" });
    const user = await User.findById(req.user.id);
    const isPinValid = await bcrypt.compare(pin, user.transactionPin);
    if (!isPinValid) return res.status(400).json({ error: "Invalid transaction PIN" });

    const result = await payBill({
      userId: req.user.id, amount, type: "CABLE",
      description: `Cable TV: ${customer}`,
      flwPayload: { country: "NG", customer, amount, type: "CABLE", item_code, code }
    });
    res.json({ success: true, message: "Cable subscription active", ...result });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ===== GROUP 3: MORE - JAMB/WAEC/BETTING =====
app.post('/api/bills/jamb',auth, async (req, res) => {
  try {
    const { country, customer, amount, item_code, code, pin } = req.body;
    if (!pin) return res.status(400).json({ error: "Transaction PIN required" });
    const user = await User.findById(req.user.id);
    const isPinValid = await bcrypt.compare(pin, user.transactionPin);
    if (!isPinValid) return res.status(400).json({ error: "Invalid transaction PIN" });

    const result = await payBill({
      userId: req.user.id, amount, type: "JAMB",
      description: `JAMB PIN`,
      flwPayload: { country: "NG", customer, amount, type: "JAMB", item_code, code }
    });
    res.json({ success: true, message: "JAMB PIN purchased", ...result });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/bills/waec',auth, async (req, res) => {
  try {
    const { country, customer, amount, item_code, code, pin } = req.body;
    if (!pin) return res.status(400).json({ error: "Transaction PIN required" });
    const user = await User.findById(req.user.id);
    const isPinValid = await bcrypt.compare(pin, user.transactionPin);
    if (!isPinValid) return res.status(400).json({ error: "Invalid transaction PIN" });

    const result = await payBill({
      userId: req.user.id, amount, type: "WAEC",
      description: `WAEC PIN`,
      flwPayload: { country: "NG", customer, amount, type: "WAEC", item_code, code }
    });
    res.json({ success: true, message: "WAEC PIN purchased", ...result });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/bills/betting',auth, async (req, res) => {
  try {
    const { country, customer, amount, item_code, code, pin } = req.body; // customer = betting ID
    if (!pin) return res.status(400).json({ error: "Transaction PIN required" });
    const user = await User.findById(req.user.id);
    const isPinValid = await bcrypt.compare(pin, user.transactionPin);
    if (!isPinValid) return res.status(400).json({ error: "Invalid transaction PIN" });

    const result = await payBill({
      userId: req.user.id, amount, type: "BETTING",
      description: `Betting: ${customer}`,
      flwPayload: { country: "NG", customer, amount, type: "BETTING", item_code, code }
    });
    res.json({ success: true, message: "Betting wallet funded", ...result });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
// FLUTTERWAVE DEPOSIT WEBHOOK HANDLER
app.post('/deposit-webhook', async (req, res) => {
  try {
    // 1. Always acknowledge the webhook immediately so Flutterwave doesn't keep retrying
    res.status(200).send("Webhook received");

    const event = req.body;

    // 2. Look specifically for successful charge events (deposits)
    if (event['event.type'] === 'CHARGE.SUCCESSFUL') {
      const paymentData = event.data;
      const amount = paymentData.amount;
      const status = paymentData.status;
      
      // Extract the userId we passed inside the 'meta' field during deposit initiation
      const userId = paymentData.meta?.userId; 
      const reference = paymentData.tx_ref;

      if (!userId) return console.log("⚠️ Webhook ignored: No userId found in metadata.");

      // 3. Prevent duplicate funding by checking if this transaction reference was already processed
      const existingTx = await Transaction.findOne({ reference: reference });
      if (existingTx) return console.log(`⚠️ Reference ${reference} already processed.`);

      // 4. If the payment status is successful, find the user and add the money
      if (status === 'successful') {
        const user = await User.findById(userId);
        if (!user) return console.log(`❌ User with ID ${userId} not found.`);

        // Add deposit amount to their app wallet balance
        user.wallet_balance += Number(amount);
        await user.save();

        // 5. Log the deposit into your MongoDB transaction history
        const depositTransaction = new Transaction({
          userId: user._id,
          type: 'credit', // Marked as a credit since money is entering the wallet
          amount: Number(amount),
          description: "Wallet Funding via Flutterwave",
          reference: reference,
          status: 'successful',
          recipient: user.account_number
        });
        await depositTransaction.save();

        console.log(`✅ Successfully funded ₦${amount} to user account: ${user.email}`);
      }
    }
  } catch (err) {
    console.error("❌ Deposit Webhook Error:", err.message);
  }
});
 // add right after app = express()
app.use(express.json());

// INITIATE FORGOT PASSWORD OTP (BREVO API VERSION)
app.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "Email required" });
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: "No user found" });
    
    const cryptoOtp = Math.floor(100000 + Math.random() * 900000).toString();
    user.resetOtpCode = cryptoOtp;
    user.resetOtpExpires = Date.now() + 10 * 60 * 1000;
    await user.save();

    // FIXED: Correct Brevo API endpoint
    const brevoResponse = await axios.post(
      'https://api.brevo.com/v3/smtp/email', // <-- THIS WAS WRONG
      {
        sender: { name: "VaultPay Security", email: "ichinegbo@gmail.com" },
        to: [{ email: email }],
        subject: "VaultPay Password Reset Code",
        htmlContent: `<p>Your OTP code is: <strong>${cryptoOtp}</strong>. It expires in 10 minutes.</p>`
      },
      {
        headers: {
          'api-key': process.env.BREVO_API_KEY,
          'Content-Type': 'application/json'
        },
        timeout: 15000
      }
    );

    console.log("✅ Brevo sent:", brevoResponse.data.messageId);
    return res.status(200).json({ success: true, message: "OTP sent" });
  } catch (err) {
    console.error("❌ Brevo Error:", err.response?.data || err.message);
    return res.status(500).json({ error: err.response?.data?.message || "Failed to send OTP" });
  }
});

// SUBMIT OTP AND UPDATE PASSWORD (RESET WINDOW CLOSURE)
app.post('/reset-password', async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;

    if (!email || !otp || !newPassword) {
      return res.status(400).json({ error: "Email, OTP code, and new password are required" });
    }
    if (newPassword.length < 6) {
      return res.status(400).json({ error: "New password must be at least 6 characters long" });
    }

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: "User profile mismatch error" });

    // Core validation gate: matches code values and looks up clock expiration states
    if (user.resetOtpCode !== otp || Date.now() > user.resetOtpExpires) {
      return res.status(400).json({ error: "Invalid or expired recovery OTP code. Try again." });
    }

    // Encrypt the fresh password hash identically using your standard 10 salt rounds
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(newPassword, salt);
    
    // Wipe out the temporary token variables from the database document profile
    user.resetOtpCode = undefined;
    user.resetOtpExpires = undefined;
    await user.save();
    res.json({ success: true, message: "Your wallet access password has been reset successfully!" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
  
});

// VA FUNDING WEBHOOK - When someone sends money to user's account_number
app.post('/webhook/flutterwave', async (req, res) => {
  try {
    res.status(200).send("OK"); // Acknowledge immediately
    
    const event = req.body;
    
    // Flutterwave sends this event when VA is credited
    if (event.event === "virtual_account.credit") {
      const data = event.data;
      const accountNumber = data.account_number;
      const amount = data.amount;
      const reference = data.reference;

      // Prevent duplicate
      const existingTx = await Transaction.findOne({ reference: reference });
      if (existingTx) return console.log(`⚠️ Reference ${reference} already processed.`);

      // Find user by account_number
      const user = await User.findOne({ account_number: accountNumber });
      if (!user) return console.log(`❌ No user found with account ${accountNumber}`);

      // Credit wallet
      user.wallet_balance += Number(amount);
      await user.save();

      // Log transaction
      const depositTransaction = new Transaction({
        userId: user._id,
        type: 'credit',
        amount: Number(amount),
        description: `Deposit from ${data.sender_name || 'Bank Transfer'}`,
        reference: reference,
        status: 'successful',
        recipient: accountNumber
      });
      await depositTransaction.save();

      console.log(`✅ Credited ₦${amount} to ${user.email}`);
    }
  } catch (err) {
    console.error("❌ VA Webhook Error:", err.message);
  }
}); 

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));