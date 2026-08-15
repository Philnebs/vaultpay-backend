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
    //CREATE TOKEN
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
app.post('/set-pin', auth, async (req, res) => {  try {
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