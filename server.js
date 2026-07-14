const express = require('express');
const mongoose = require('mongoose');
require('dotenv').config();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
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
  account_number: { type: String, unique: true }, // ADD THIS ON LINE 22
  wallet_balance: { type: Number, default: 1000.00 },
  created_at: { type: Date, default: Date.now }
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
  recipient: { type: String }, // account name or phone
  date: { type: Date, default: Date.now }
});

const Transaction = mongoose.model('Transaction', transactionSchema);

// AUTH MIDDLEWARE
const auth = async (req, res, next) => {
  try {
    const token = req.header('Authorization');
    if (!token) return res.status(401).json({ error: "No token, access denied" });

    const decoded = jwt.verify(token.replace('Bearer ', ''), process.env.JWT_SECRET);
    req.user = decoded.id;
    next();
  } catch (err) {
    res.status(401).json({ error: "Token is not valid" });
  }
};

//// REGISTER
app.post('/register', async (req, res) => {
  try {
    const { name, email, phone, password } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Generate 10 digit account number
    const account_number = Math.floor(1000000 + Math.random() * 9000000).toString();

    const user = new User({ name, email, phone, password: hashedPassword, account_number, wallet_balance: 1000 });
    await user.save();

    const { password: _, ...userWithoutPassword } = user.toObject();

    res.status(201).json({ message: "User created", user: userWithoutPassword });
  } catch (err) {
    res.status(500).json({ error: err.message });
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
    
    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "7d" });
    
    const { password: _, ...userWithoutPassword } = user.toObject();
    res.json({ message: "Login successful", token, user: userWithoutPassword });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// BALANCE - SECURE
app.get('/balance', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    res.json({ 
      name: user.name,
      account_number: user.account_number,
      balance: user.wallet_balance 
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
// SEND MONEY ROUTE
app.post('/send', auth, async (req, res) => {
  try {
    const { toAccountNumber, amount } = req.body;
    
   const sender = await User.findById(req.user);
    const receiver = await User.findOne({ account_number: toAccountNumber });
    
    if (!receiver) return res.status(404).json({ error: "Account number not found" });
    if (amount <= 0) return res.status(400).json({ error: "Amount must be greater than 0" });
    if (sender.wallet_balance < amount) return res.status(400).json({ error: "Insufficient balance" });
    if (sender._id.equals(receiver._id)) return res.status(400).json({ error: "Cannot send to yourself" });
    
    // Transfer
    sender.wallet_balance -= amount;
    receiver.wallet_balance += amount;
    
    await sender.save();
    await receiver.save();
    
    res.json({ 
      message: `Sent ₦${amount} to ${receiver.name}`, 
      yourNewBalance: sender.wallet_balance 
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
// DEPOSIT MONEY ROUTE - NEW WITH FLUTTERWAVE
app.post('/deposit', auth, async (req, res) => {
  try {
    const { amount } = req.body;
    const user = await User.findById(req.user);

    if (amount <= 0) return res.status(400).json({ error: "Amount must be greater than 0" });

    const tx_ref = `VTP_FUND_${Date.now()}`;

    const payload = {
      tx_ref: tx_ref,
      amount: amount,
      currency: "NGN",
      redirect_url: "https://swiftpay-backend-v2.onrender.com/payment-success", // you can change this later
      customer: {
        email: user.email,
        name: user.fullName
      },
      meta: {
        userId: user._id.toString() // IMPORTANT: so webhook knows who to credit
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


// WITHDRAW MONEY ROUTE
app.post('/withdraw', auth, async (req, res) => {
  try {
    const { amount } = req.body;
    const user = await User.findById(req.user);

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

const axios = require('axios');
const FLW_SECRET_KEY = process.env.FLW_SECRET_KEY;

// 1. GET ALL NIGERIAN BANKS
app.get('/banks', async (req, res) => {
  try {
    const response = await axios.get('https://api.flutterwave.com/v3/banks/NG', {
      headers: { Authorization: `Bearer ${FLW_SECRET_KEY}` }
    });
    res.json(response.data); // returns list of banks + codes
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
// 3. VERIFY ACCOUNT NAME BEFORE TRANSFER
app.post('/verify-account', auth, async (req, res) => {
  try {
    const { account_number, bank_code } = req.body;

    if (!account_number || !bank_code) 
      return res.status(400).json({ error: "account_number and bank_code are required" });

    const payload = {
      account_number: account_number,
      account_bank: bank_code
    };

    const flwResponse = await axios.post(
      'https://api.flutterwave.com/v3/accounts/resolve', 
      payload,
      {
        headers: { Authorization: `Bearer ${FLW_SECRET_KEY}` }
      }
    );

    res.json({
      message: "Account verified",
      account_name: flwResponse.data.data.account_name
    });

  } catch (err) {
    res.status(400).json({ 
      error: err.response?.data?.message || "Account not found" 
    });
  }
});
// 2. SEND MONEY TO ANY BANK
app.post('/bank-transfer', auth, async (req, res) => {
  try {
    const { bank_code, account_number, amount, narration } = req.body;

    if (!account_number || !bank_code || !amount) 
      return res.status(400).json({ error: "account_number, bank_code and amount are required" });

    const user = await User.findById(req.user);

    if (user.wallet_balance < amount) 
      return res.status(400).json({ error: "Insufficient funds" });

    // Step 1: Verify account with Flutterwave first
    const verifyPayload = { 
      account_number: account_number, 
      account_bank: bank_code 
    };
    const verifyResponse = await axios.post(
      'https://api.flutterwave.com/v3/accounts/resolve',
      verifyPayload,
      { headers: { Authorization: `Bearer ${FLW_SECRET_KEY}` } }
    );
    const account_name = verifyResponse.data.data.account_name;

    // Step 2: Deduct from VaultPay wallet
    user.wallet_balance -= amount;
    await user.save();
    // Step 2.5: Save Transaction to History
    const newTransaction = new Transaction({
      userId: user._id,
      type: 'debit',
      amount: amount,
      description: `Transfer to ${account_name}`,
      reference: `VTP_${Date.now()}`,
      recipient: account_name
    });
    await newTransaction.save();

    // Step 3: Tell Flutterwave to send the money
    const transferPayload = {
      account_bank: bank_code,
      account_number: account_number,
      amount: amount,
      narration: narration || `VaultPay transfer to ${account_name}`,
      currency: "NGN",
      reference: `VTP_${Date.now()}`,
      beneficiary_name: account_name
    };

    const flwResponse = await axios.post(
      'https://api.flutterwave.com/v3/transfers',
      transferPayload,
      { headers: { Authorization: `Bearer ${FLW_SECRET_KEY}` }
  });

    res.json({
      message: "Transfer successful",
      account_name: account_name,
      flutterwave_response: flwResponse.data,
      newBalance: user.wallet_balance
    });

  } catch (err) {
    res.status(500).json({ error: err.response?.data || err.message });
  }
});
   const PORT = 5000; // change from 3000 to 5000
   // 5. GET TRANSACTION HISTORY
app.get('/transactions', auth, async (req, res) => {
  try {
    const transactions = await Transaction.find({ userId: req.user })
      .sort({ date: -1 }) // newest first
      .limit(20); // last 20 transactions

    res.json({
      message: "Transaction history",
      count: transactions.length,
      transactions: transactions
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
// 6. BUY AIRTIME, DATA, BILLS
app.post('/bills', auth, async (req, res) => {
  try {
    const { type, biller_code, item_code, amount, phone } = req.body;
    // type: 'airtime', 'data', 'dstv', 'gotv', 'jamb'
    // biller_code: 'MTN', 'GLO', 'DSTV'
    // item_code: 'mtn-10' for 10 naira airtime, 'dstv-padi' for padi package

    const user = await User.findById(req.user);
    if (user.wallet_balance < amount) {
      return res.status(400).json({ message: 'Insufficient balance' });
    }

    // Step 1: Deduct from VaultPay wallet first
    user.wallet_balance -= amount;
    await user.save();

    // Step 2: Call Flutterwave to buy the bill
    const billPayload = {
      country: "NG",
      customer: phone,
      amount: amount,
      type: type, // airtime, data, dstv, jamb
      reference: `VTP_BILL_${Date.now()}`,
      biller_code: biller_code,
      item_code: item_code
    };

    const billResponse = await axios.post(
      'https://api.flutterwave.com/v3/bills',
      billPayload,
      { headers: { Authorization: `Bearer ${FLW_SECRET_KEY}` }
  });

    // Step 3: Save to Transaction History
    const newTransaction = new Transaction({
      userId: user._id,
      type: 'debit',
      amount: amount,
      description: `${type.toUpperCase()} - ${biller_code} - ${phone}`,
      reference: billPayload.reference,
      recipient: phone,
      status: billResponse.data.status === 'success' ? 'successful' : 'pending'
    });
    await newTransaction.save();

    res.status(200).json({
      message: `${type} purchase successful`,
      data: billResponse.data
    });
} catch (err) {
  console.log("FLUTTERWAVE ERROR:",err.response.data); // <-- add this
  res.status(500).json({ error: err.response.data });
}
});
// FLUTTERWAVE WEBHOOK ROUTE
app.post('/api/webhook', async (req, res) => {
  try {
    // 1. Verify it’s from Flutterwave
    const secretHash = process.env.FLW_SECRET_HASH;
    const signature = req.headers["verif-hash"];
    
    if (!signature || signature !== secretHash) {
      return res.status(401).json({ message: 'Unauthorized' });
    }

    const payload = req.body;
    console.log("WEBHOOK RECEIVED:", payload.tx_ref);

    // 2. Only process successful wallet funding
    if (payload.status === "successful" && payload.tx_ref.startsWith("VTP_FUND_")) {
      const userId = payload.meta.userId;
      const amount = payload.amount;

      // 3. Credit user wallet
      const user = await User.findById(userId);
      user.wallet_balance += amount;
      await user.save();

      // 4. Save transaction
      const newTransaction = new Transaction({
        userId: user._id,
        type: 'credit',
        amount: amount,
        description: 'Wallet Funding',
        reference: payload.tx_ref,
        status: 'success'
      });
      await newTransaction.save();
    }
    
    res.status(200).send("OK"); // MUST return 200
  } catch (err) {
    console.log("WEBHOOK ERROR:", err.message);
    res.status(500).json({ error: err.message });
  }
});
// 404 HANDLER - tells us what route was not found
app.use((req, res) => {
  console.log(`404: ${req.method} ${req.url}`); // this will show in Render logs
  res.status(404).json({ 
    message: 'Route not found', 
    path: req.url,
    method: req.method,
    tip: 'Did you mean /register or /login?'
  });
});


app.listen(PORT, () => console.log(`Server running on port ${PORT}`));