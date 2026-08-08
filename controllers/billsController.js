const axios = require("axios");

const VTPASS_URL = "https://api-service.vtpass.com/api";
const headers = {
  "api-key": process.env.VTPASS_API_KEY,
  "secret-key": process.env.VTPASS_SECRET_KEY
};

// 1. GET CATEGORIES
exports.getCategories = async (req, res) => {
  try {
    const { type } = req.query; // power, cabletv, airtime, data
    const vtRes = await axios.get(`${VTPASS_URL}/service-variations?serviceID=${type}`, { headers });
    res.json({ success: true, data: vtRes.data.content?.variations || vtRes.data.content || [] });
  } catch (e) {
    console.error(e.response?.data);
    res.status(500).json({ success: false, message: e.message });
  }
};

// 2. GET ITEMS/PACKAGES
exports.getBillItems = async (req, res) => {
  try {
    const { serviceID } = req.body;
    const vtRes = await axios.get(`${VTPASS_URL}/service-variations?serviceID=${serviceID}`, { headers });
    res.json({ success: true, data: vtRes.data.content?.variations || vtRes.data.content || [] });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
};

// 3. VALIDATE METER/SMARTCARD
exports.validateBill = async (req, res) => {
  try {
    const { billersCode, serviceID, type } = req.body;
    const vtRes = await axios.post(`${VTPASS_URL}/merchant-verify`, { billersCode, serviceID, type }, { headers });
    res.json({ success: true, data: vtRes.data });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
};

// 4. PAY BILL
exports.payBill = async (req, res) => {
  try {
    const payload = req.body; // billersCode, serviceID, variation_code, amount, phone, request_id
    const vtRes = await axios.post(`${VTPASS_URL}/pay`, payload, { headers });
    res.json({ success: true, data: vtRes.data });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
};
// 5. GET ALL VTPASS SERVICES FOR "MORE" SCREEN
exports.getVtpassServices = async (req, res) => {
  try {
    const vtRes = await axios.get(`${VTPASS_URL}/service-categories`, { headers });
    res.json({ 
      success: true, 
      data: vtRes.data.content?.categories || vtRes.data.content || [] 
    });
  } catch (e) {
    console.error("VTpass Error:", e.response?.data);
    res.status(500).json({ success: false, message: e.message });
  }
};

// 6. PAY VTPASS SERVICES - JAMB/WAEC/BETTING
exports.payVtpass = async (req, res) => {
  try {
    const payload = req.body; // serviceID, billersCode, variation_code, amount, phone, request_id
    const vtRes = await axios.post(`${VTPASS_URL}/pay`, payload, { headers });
    res.json({ success: true, data: vtRes.data });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
};