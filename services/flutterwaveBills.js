const axios = require("axios");

const FLW_BASE_URL = "https://api.flutterwave.com/v3";

const headers = {
  Authorization: `Bearer ${process.env.FLW_SECRET_KEY}`,
  "Content-Type": "application/json",
};

// ===============================
// GET BILL CATEGORIES
// ===============================
async function getCategories(type = null) {
  try {
    const url = type
      ? `${FLW_BASE_URL}/bill-categories?type=${type}`
      : `${FLW_BASE_URL}/bill-categories`;

    const response = await axios.get(url, { headers });

    return response.data;

  } catch (error) {
    throw new Error(
      error.response?.data?.message || error.message
    );
  }
}

// ===============================
// GET BILL ITEMS / PLANS
// ===============================
async function getBillItems(itemCode) {
  try {
    const response = await axios.get(
      `${FLW_BASE_URL}/bill-items/${itemCode}`,
      { headers }
    );

    return response.data;

  } catch (error) {
    throw new Error(
      error.response?.data?.message || error.message
    );
  }
}

// ===============================
// VALIDATE CUSTOMER
// ===============================
async function validateCustomer(itemCode, code, customer) {

  try {

    const response = await axios.get(

      `${FLW_BASE_URL}/bill-items/${itemCode}/validate?code=${code}&customer=${customer}`,

      { headers }

    );

    return response.data;

  } catch (error) {

    throw new Error(

      error.response?.data?.message || error.message

    );

  }

}

module.exports = {

  getCategories,

  getBillItems,

  validateCustomer,

};