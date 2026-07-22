const express = require('express');
const mongoose = require('mongoose');
require('dotenv').config();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const axios = require('axios'); // Moved to the top for consistency

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
  account_number: { type: String, unique: true },
  wallet_balance: { type: Number, default: 1000.00 },
  created_at: { type: Date, default: Date.now },
  transactionPin: { type: String }
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

// REGISTER
app.post('/register', async (req, res) => {
  try {
    const { name, email, phone, password } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Generate 10 digit account number
    const account_number = Math.floor(1000000000 + Math.random() * 9000000000).toString();

    const user = new User({ name, email, phone, password: hashedPassword, account_number, wallet_balance: 1000 });
    await user.save();

    const { password: _, ...userWithoutPassword } = user.toObject();

    const token = jwt.sign(
      { id: user._id }, 
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(201).json({ 
      message: "User created", 
      token: token,
      user: userWithoutPassword 
    });
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
      callback_url: "https://onrender.com" // Adjust as needed
    };

    // 7. Make the live API Call to Flutterwave to execute the transfer
    const response = await axios.post(
      'https://flutterwave.com',
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

// VERIFY ACCOUNT NAME
app.post('/verify-account', auth, async (req, res) => {
  try {
    const { account_number, bank_code } = req.body;

    if (!account_number || !bank_code) 
      return res.status(400).json({ error: "account_number and bank_code are required" });

    const response = await axios.post('https://flutterwave.com', {
      account_number,
      account_bank: bank_code
    }, {
      headers: { Authorization: `Bearer ${FLW_SECRET_KEY}` }
    });
    
    res.json(response.data);
  } catch (err) {
    res.status(500).json({ error: err.message });
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
// 1. FETCH AVAILABLE BILLS (DSTV, GOTV, ELECTRICITY, WAEC, JAMB)
app.get('/bills/categories', auth, async (req, res) => {
  try {
    const { type } = req.query; // 'airtime', 'data_bundle', 'power', 'cable', 'utility'
    
    const url = type 
      ? `https://api.flutterwave.com/v3/bill-categories?type=${type}` 
      : 'https://api.flutterwave.com/v3/bill-categories';

    const response = await axios.get(url, {
      headers: { Authorization: `Bearer ${process.env.FLW_SECRET_KEY}` }
    });

    res.json({
      success: true,
      categories: response.data
    });
  } catch (err) {
    console.log(err.response?.data)
    res.status(500).json({ error: `Failed to fetch categories: ${err.response?.data?.message || err.message}` });
  }
});

// 2. VALIDATE CUSTOMER BILL DETAILS
app.post('/bills/validate', auth, async (req, res) => {
  try {
    const { item_code, code, customer } = req.body;

    if (!item_code || !code || !customer) {
      return res.status(400).json({ error: "item_code, code, and customer are required" });
    }

    const response = await axios.get(
      `https://api.flutterwave.com/v3/bill-items/${item_code}/validate?code=${code}&customer=${customer}`,
      { headers: { Authorization: `Bearer ${process.env.FLW_SECRET_KEY}` } }
    );

    res.json({
      success: true,
      customerDetails: response.data
    });
  } catch (err) {
    console.log(err.response?.data)
    res.status(500).json({ error: `Validation failed: ${err.response?.data?.message || err.message}` });
  }
});

// 3. EXECUTE BILL PAYMENT
app.post('/bills/pay', auth, async (req, res) => {
  try {
    const { country, customer, amount, type, pin, description, item_code, code } = req.body;

    if (!country || !customer || !amount || !type || !pin || !item_code || !code) {
      return res.status(400).json({ error: "Missing required bill payment fields" });
    }
    if (amount <= 0) return res.status(400).json({ error: "Amount must be greater than 0" });

    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: "User profile not found" });

    const isPinValid = await bcrypt.compare(pin, user.transactionPin);
    if (!isPinValid) return res.status(400).json({ error: "Invalid transaction PIN" });

    if (user.wallet_balance < amount) {
      return res.status(400).json({ error: "Insufficient wallet balance" });
    }

    const uniqueReference = `VTP_BILL_${Date.now()}_${Math.floor(Math.random() * 1000)}`;

    // 1. DEDUCT FIRST
    user.wallet_balance -= amount;
    await user.save();

    try {
      // 2. PAY FLUTTERWAVE
      const response = await axios.post(
        'https://api.flutterwave.com/v3/bills',
        {
          country: country || "NG",
          customer: customer, 
          amount: Number(amount),
          type: type, 
          reference: uniqueReference,
          item_code: item_code,
          code: code,
          recurrence: "ONCE"
        },
        { headers: { Authorization: `Bearer ${process.env.FLW_SECRET_KEY}` } }
      );

      if (response.data.status !== "success") {
        user.wallet_balance += amount; // REFUND
        await user.save();
        return res.status(400).json({ error: response.data.message });
      }

      // 3. LOG TRANSACTION
      const newTransaction = new Transaction({
        userId: user._id,
        type: 'debit',
        amount: amount,
        description: description || `Bill Payment: ${type}`,
        reference: uniqueReference,
        status: 'successful',
        recipient: customer
      });
      await newTransaction.save();

      res.json({
        success: true,
        message: "Bill payment processed successfully",
        newBalance: user.wallet_balance,
        billDetails: response.data
      });

    } catch (flwErr) {
      user.wallet_balance += amount; // REFUND
      await user.save();
      throw flwErr;
    }

  } catch (err) {
    console.log(err.response?.data)
    res.status(500).json({ error: `Bill payment failed: ${err.response?.data?.message || err.message}` });
  }
});

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
