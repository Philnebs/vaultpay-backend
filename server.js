const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const axios = require("axios");
require("dotenv").config();

const app = express();
app.use(express.json());
app.use(cors());

const JWT_SECRET = process.env.JWT_SECRET || "vaultpay_secret_2026";
const FLW_SECRET = process.env.FLUTTERWAVE_SECRET_KEY;

// ========== FUNCTION TO GENERATE 10 DIGIT ACCOUNT NUMBER ==========
const generateAccountNumber = () => {
  // Generates random 10 digit number starting with 069
  return "069" + Math.floor(1000000 + Math.random() * 9000000).toString();
};

// ========== 3. DATABASE MODEL ==========
const User = mongoose.model("User", new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  phone: String,
  accountNumber: { type: String, unique: true }, // ADDED: 10 digit account number
  balance: { type: Number, default: 5000 },
  transactionPin: String,
}));

// ========== 4. AUTH MIDDLEWARE ==========
const auth = async (req, res, next) => {
  try {
    const token = req.header("Authorization")?.replace("Bearer ", "");
    if (!token) return res.status(401).json({ error: "No token" });
    
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = { id: decoded.id };
    
    const user = await User.findById(req.user.id);
    if (!user) return res.status(401).json({ error: "User not found" });
    
    req.userData = user;
    next();
  } catch (e) {
    res.status(401).json({ error: "Invalid token" });
  }
};

// ========== 5. ROUTES ==========

// REGISTER - NOW GENERATES ACCOUNT NUMBER
app.post("/register", async (req, res) => {
  try {
    const { name, email, password, phone } = req.body;
    const hashed = await bcrypt.hash(password, 10);
    
    let accountNumber;
    let userExists = true;
    // Loop until we get a unique account number
    while(userExists){
      accountNumber = generateAccountNumber();
      userExists = await User.findOne({ accountNumber });
    }

    const user = await User.create({ 
      name, 
      email, 
      password: hashed, 
      phone,
      accountNumber // Save the 10 digit number
    });
    
    res.json({ 
      message: "User created successfully",
      accountNumber: user.accountNumber, // Return it to user
      balance: user.balance
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !await bcrypt.compare(password, user.password))
      return res.status(400).json({ error: "Invalid login" });
    
    const token = jwt.sign({ id: user._id.toString() }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ token, accountNumber: user.accountNumber }); // Return account number on login too
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/set-pin", auth, async (req, res) => {
  try {
    const { pin } = req.body;
    const hashedPin = await bcrypt.hash(pin, 10);
    await User.findByIdAndUpdate(req.user.id, { transactionPin: hashedPin });
    res.json({ message: "PIN set successfully" });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// BANK TRANSFER - NOW CAN SEND TO WALLET OR BANK
app.post("/bank-transfer", auth, async (req, res) => {
  try {
    const { account_number, bank_code, amount, pin, description } = req.body;
    
    if (!account_number || !amount || !pin)
      return res.status(400).json({ error: "account_number, amount and pin are required" });

    const user = req.userData;
    
    const validPin = await bcrypt.compare(pin, user.transactionPin);
    if (!validPin) return res.status(400).json({ error: "Invalid Transaction PIN" });
    if (user.balance < amount) return res.status(400).json({ error: "Insufficient balance" });

    // IF bank_code is provided, it's external bank. If not, it's wallet to wallet
    if(bank_code){
      // EXTERNAL BANK TRANSFER VIA FLUTTERWAVE
      const flwResponse = await axios.post(
        "https://api.flutterwave.com/v3/transfers",
        {
          account_bank: bank_code,
          account_number: account_number,
          amount: amount,
          narration: description || "VaultPay Transfer",
          currency: "NGN",
          reference: `VP_${Date.now()}`
        },
        { headers: { Authorization: `Bearer ${FLW_SECRET}` } }
      );

      if(flwResponse.data.status === "success"){
        user.balance -= amount;
        await user.save();
        return res.json({ message: "Bank transfer successful", new_balance: user.balance });
      } else {
        return res.status(400).json({ error: flwResponse.data.message });
      }
    } else {
      // WALLET TO WALLET TRANSFER - Find user by accountNumber
      const receiver = await User.findOne({ accountNumber: account_number });
      if(!receiver) return res.status(400).json({ error: "Receiver account not found" });
      
      user.balance -= amount;
      receiver.balance += amount;
      await user.save();
      await receiver.save();
      return res.json({ message: "Wallet transfer successful", new_balance: user.balance });
    }

  } catch (e) {
    console.log("ERROR:", e.response?.data || e.message);
    res.status(500).json({ error: e.response?.data?.message || "Transfer failed" });
  }
});

mongoose.connect(process.env.MONGO_URI)
.then(() => app.listen(process.env.PORT || 5000, () => console.log("Server running")));