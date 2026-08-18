const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const axios = require('axios');
require('dotenv').config();

const app = express();
const JWT_SECRET = process.env.JWT_SECRET;

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
  created_at: { type: Date, default: Date.now }
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
      return res.status(400).json({ error: "All fields and BVN are required." });
    }
    const normalizedEmail = email.toLowerCase().trim();
    const existingUser = await User.findOne({ email: normalizedEmail });
    if (existingUser && existingUser.isVerified) {
      return res.status(400).json({ error: "Email already registered." });
    }

        const registrationOtp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpiryTime = Date.now() + 15 * 60 * 1000;
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    await User.findOneAndUpdate(
      { email: normalizedEmail },
      {
        name: name.trim(),
        phone: phone.trim(),
        password: hashedPassword,
        otpCode: registrationOtp,
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
        htmlContent: `<p>Hello ${name},</p><p>Your registration code is: <strong>${registrationOtp}</strong>. It expires in 15 minutes.</p>`
      },
      { headers: { 'api-key': process.env.BREVO_API_KEY, 'Content-Type': 'application/json' }, timeout: 15000 }
    );

    return res.status(200).json({ success: true, message: "Verification OTP sent to email." });
  } catch (err) {
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


        const nameParts = (user.name || "User VaultPay").split(" ");
    const firstName = nameParts[0] || "User";
    const lastName = nameParts.slice(1).join(" ") || "VaultPay";
    const cleanPhone = (user.phone || '').replace(/\D/g, '');

    const flwResponse = await axios.post(
      'https://api.flutterwave.com/v3/virtual-account-numbers',
      {
        email: normalizedEmail,
        is_permanent: true,
        bvn: bvn.toString().trim(),
        tx_ref: `VP-REF-${Date.now()}`,
        firstname: firstName,
        lastname: lastName,
        phonenumber: cleanPhone
      },
      { headers: { Authorization: `Bearer ${process.env.FLW_SECRET_KEY}`, 'Content-Type': 'application/json' }, timeout: 18000 }
    );

    if (flwResponse.data.status !== 'success') {
      return res.status(400).json({ error: "Routing allocation failed.", details: flwResponse.data.message });
    }
    const flwData = flwResponse.data.data;

        const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "7d" });

    user.isVerified = true;
    user.account_number = flwData.account_number;
    user.bank_name = flwData.bank_name; 
    user.account_name = flwData.account_name;
    user.otpCode = undefined;
    user.otpExpires = undefined;
    user.wallet_balance = 0.00;
    await user.save();

    return res.status(200).json({
      success: true,
      message: "Account active!",
      token,
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
    return res.status(500).json({ error: "Verification failed.", details: errorMsg });
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
        callback_url: "https://yourdomain.com"
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

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 VaultPay Server running on port ${PORT}`));
