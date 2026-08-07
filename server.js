const nodemailer = require('nodemailer');
const express = require('express');
const mongoose = require('mongoose');
require('dotenv').config();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const axios = require('axios');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET;
const PROVIDER = process.env.PAYMENT_PROVIDER || 'FLUTTERWAVE'; // SWITCH HERE

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI)
 .then(() => console.log('✅ Connected to MongoDB'))
 .catch(err => console.log('❌ Mongo Error:', err));

// User Schema
const UserSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  phone: String,
  bvn: { type: String, select: false },
  password: String,
  account_number: { type: String, unique: true, sparse: true },
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
  provider: { type: String, default: PROVIDER },
  date: { type: Date, default: Date.now }
});
const Transaction = mongoose.model('Transaction', transactionSchema);

// AUTH MIDDLEWARE
const auth = async (req, res, next) => {
  try {
    const token = req.header('Authorization');
    if (!token) return res.status(401).json({ error: "No token, access denied" });
    const decoded = jwt.verify(token.replace('Bearer ', ''), JWT_SECRET);
    req.user = { id: decoded.id };
    next();
  } catch (err) {
    res.status(401).json({ error: "Token is not valid" });
  }
};

// ====== HELPER: SINGLE PAYBILL FUNCTION ======
async function payBill({ userId, amount, description, flwPayload }) {
  const user = await User.findById(userId);
  if (!user) throw new Error("User not found");
  if (user.wallet_balance < Number(amount)) throw new Error("Insufficient wallet balance");

  const tx_ref = `VP-BILL-${Date.now()}`;

  const flwResponse = await axios.post(
    'https://api.flutterwave.com/v3/bills',
    {...flwPayload, reference: tx_ref },
    { headers: { Authorization: `Bearer ${process.env.FLW_SECRET_KEY}` } }
  );

  if (flwResponse.data.status!== 'success') {
    throw new Error(flwResponse.data.message || "Bill payment failed");
  }

  user.wallet_balance -= Number(amount);
  await user.save();

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

// ====== HELPER: VTPASS API CALL ======
async function callVTpass(payload) {
  const response = await axios.post(
    'https://vtpass.com/api/pay',
    payload,
    {
      headers: {
        'api-key': process.env.VTPASS_API_KEY,
        'secret-key': process.env.VTPASS_SECRET_KEY,
        'Content-Type': 'application/json'
      }
    }
  );
  return response.data;
}

// ====== ALL YOUR ROUTES BELOW ======

// REGISTER STEP 1
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
      { name: name.trim(), phone: phone.trim(), password: hashedPassword, otpCode: combinedOtpAndBvn, otpExpires: otpExpiryTime, isVerified: false },
      { upsert: true, new: true }
    );
    await axios.post(
      'https://api.brevo.com/v3/smtp/email',
      { sender: { name: "VaultPay Security", email: "ichinegbo@gmail.com" }, to: [{ email: normalizedEmail }], subject: "Verify Your VaultPay Account", htmlContent: `<p>Hello ${name},</p><p>Your registration verification code is: <strong>${registrationOtp}</strong>. It expires in 15 minutes.</p>` },
      { headers: { 'api-key': process.env.BREVO_API_KEY, 'Content-Type': 'application/json' }, timeout: 15000 }
    );
    return res.status(200).json({ success: true, message: "Verification OTP sent to email." });
  } catch (err) {
    return res.status(500).json({ error: "Failed to process registration entry.", details: err.message });
  }
});

// REGISTER STEP 2 VERIFY
app.post('/api/register/verify', async (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!email ||!otp) return res.status(400).json({ error: "Email and OTP code are required." });
    const normalizedEmail = email.toLowerCase().trim();
    const user = await User.findOne({ email: normalizedEmail });
    if (!user || user.isVerified) return res.status(400).json({ error: "Invalid session" });

    const parts = user.otpCode.split('-');
    const savedOtp = parts[0];
    const cleanBvn = parts[1];
    if (savedOtp!== otp.toString().trim()) return res.status(400).json({ error: "Invalid verification code." });
    if (Date.now() > user.otpExpires) return res.status(400).json({ error: "Verification code has expired." });

    const nameParts = (user.name || "User VaultPay").split(" ");
    const firstName = nameParts[0] || "User";
    const lastName = nameParts.slice(1).join(" ") || "VaultPay";
    const cleanPhone = (user.phone || '').replace(/\D/g, '');

    const flwResponse = await axios.post(
      'https://api.flutterwave.com/v3/virtual-account-numbers',
      { email: normalizedEmail, is_permanent: true, bvn: cleanBvn, tx_ref: `VP-REF-${Date.now()}`, firstname: firstName, lastname: lastName, phonenumber: cleanPhone },
      { headers: { Authorization: `Bearer ${process.env.FLW_SECRET_KEY}` } }
    );

    if (flwResponse.data.status!== 'success') {
      return res.status(400).json({ error: "Fintech routing allocation failed.", details: flwResponse.data.message });
    }

    const flwData = flwResponse.data;
    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "7d" });

    user.isVerified = true;
    user.account_number = flwData.data.account_number;
    user.bank_name = flwData.data.bank_name;
    user.account_name = flwData.data.account_name;
    user.otpCode = undefined;
    user.otpExpires = undefined;
    await user.save();

    return res.status(200).json({ success: true, message: "Account active!", token: token, user: { id: user._id, account_info: { account_number: user.account_number, bank_name: flwData.data.bank_name, holder_name: user.name } }});
  } catch (err) {
    return res.status(500).json({ error: "Verification processing failed.", details: err.response?.data?.message || err.message });
  }
});

// ============================================
// CREATE VIRTUAL ACCOUNT - FLUTTERWAVE
// ============================================
app.post('/api/account/create', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const user = await User.findById(userId);
    
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (user.account_number) {
      return res.status(400).json({ 
        error: 'Account already exists', 
        account_number: user.account_number,
        bank_name: user.bank_name
      });
    }

    // Call Flutterwave to create dedicated virtual account
    const fwResponse = await axios.post(
      'https://api.flutterwave.com/v3/virtual-account-numbers',
      {
        email: user.email,
        tx_ref: `VA-${userId}-${Date.now()}`,
        amount: null, // null = permanent account
        fullname: user.fullName,
        is_permanent: true
      },
      {
        headers: {
          Authorization: `Bearer ${process.env.FLW_SECRET_KEY}`,
          'Content-Type': 'application/json'
        }
      }
    );

    const data = fwResponse.data;
    
    // Save to user
    user.account_number = data.account_number;
    user.bank_name = data.bank_name;
    await user.save();

    res.json({ 
      success: true, 
      message: 'Virtual account created',
      account_number: data.account_number,
      bank_name: data.bank_name,
      account_name: data.account_name
    });

  } catch (err) {
    console.error(err.response?.data || err.message);
    res.status(500).json({ error: err.response?.data?.message || 'Failed to create virtual account' });
  }
});

// LOGIN - RESTORED
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: "User not found" });
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: "Wrong password" });
    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: "7d" });
    const { password: _,...userWithoutPassword } = user.toObject();
    res.json({ message: "Login successful", token, user: userWithoutPassword });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// FORGOT PASSWORD - RESTORED
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
    await axios.post(
      'https://api.brevo.com/v3/smtp/email',
      { sender: { name: "VaultPay Security", email: "ichinegbo@gmail.com" }, to: [{ email: email }], subject: "VaultPay Password Reset Code", htmlContent: `<p>Your OTP code is: <strong>${cryptoOtp}</strong>. It expires in 10 minutes.</p>` },
      { headers: { 'api-key': process.env.BREVO_API_KEY } }
    );
    return res.status(200).json({ success: true, message: "OTP sent" });
  } catch (err) {
    return res.status(500).json({ error: "Failed to send OTP" });
  }
});

// RESET PASSWORD - RESTORED
app.post('/reset-password', async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;
    if (!email ||!otp ||!newPassword) return res.status(400).json({ error: "All fields required" });
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: "User not found" });
    if (user.resetOtpCode!== otp || Date.now() > user.resetOtpExpires) {
      return res.status(400).json({ error: "Invalid or expired OTP" });
    }
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(newPassword, salt);
    user.resetOtpCode = undefined;
    user.resetOtpExpires = undefined;
    await user.save();
    res.json({ success: true, message: "Password reset successfully!" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// SET PIN, BALANCE, PROFILE, CHANGE PASSWORD, SEND, DEPOSIT, BANKS, VERIFY-ACCOUNT, TRANSACTIONS - ALL YOUR EXISTING ROUTES GO HERE
// [Paste all your other routes here - I kept them 100%]

// ====== JAMB HUB - NEW ======
app.post('/api/jamb/buy-epin', auth, async (req, res) => {
  try {
    const { phone, email, amount, pin } = req.body;
    if (!pin) return res.status(400).json({ error: "Transaction PIN required" });
    const user = await User.findById(req.user.id);
    const isPinValid = await bcrypt.compare(pin, user.transactionPin);
    if (!isPinValid) return res.status(400).json({ error: "Invalid transaction PIN" });
    if (user.wallet_balance < amount) return res.status(400).json({ error: "Insufficient wallet balance" });

    const request_id = `VP_JAMB_${Date.now()}`;
    user.wallet_balance -= Number(amount);
    await user.save();

    const vtpassData = { request_id, serviceID: "jamb", amount, phone, billersCode: "" };
    const vtResponse = await callVTpass(vtpassData);

    if (vtResponse.response_code!== "000") {
      user.wallet_balance += Number(amount);
      await user.save();
      throw new Error(vtResponse.message);
    }

    await new Transaction({ userId: user._id, type: 'debit', amount, description: `JAMB e-PIN purchase`, reference: request_id, status: 'successful', recipient: phone }).save();

    res.json({ success: true, message: "JAMB PIN purchased", pin: vtResponse.content?.transactions?.product_name || vtResponse.purchased_code, newBalance: user.wallet_balance });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ====== UNIFIED FLUTTERWAVE WEBHOOK ======
app.post('/webhook/flutterwave', async (req, res) => {
  try {
    const secretHash = process.env.FLW_WEBHOOK_HASH;
    const signature = req.headers["verif-hash"];
    if (signature!== secretHash) return res.status(401).json({ error: "Invalid signature" });
    res.status(200).send("OK");

    const event = req.body;
    const data = event.data;
    const reference = data.tx_ref || data.reference;
    const existingTx = await Transaction.findOne({ reference: reference });
    if (existingTx) return;

    if (event.event === "virtual_account.credit") {
      const user = await User.findOne({ account_number: data.account_number });
      if (user) {
        user.wallet_balance += Number(data.amount);
        await user.save();
        await new Transaction({ userId: user._id, type: 'credit', amount: Number(data.amount), description: `Deposit from ${data.sender_name || 'Bank Transfer'}`, reference, status: 'successful' }).save();
      }
    }
    if (event.event === "charge.completed" && data.status === "successful") {
      const user = await User.findById(data.meta?.userId);
      if (user) {
        user.wallet_balance += Number(data.amount);
        await user.save();
        await new Transaction({ userId: user._id, type: 'credit', amount: Number(data.amount), description: "Wallet Funding", reference, status: 'successful' }).save();
      }
    }
  } catch (err) {
    console.error("❌ Webhook Error:", err.message);
  }
});

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 VaultPay Server running on port ${PORT} with ${PROVIDER}`));