const flutterwave = require("./flutterwaveBills");

// Current bill provider
const ACTIVE_PROVIDER = "flutterwave";

// ===============================
// GET CATEGORIES
// ===============================
async function getCategories(type) {

    switch (ACTIVE_PROVIDER) {

        case "flutterwave":
            return await flutterwave.getCategories(type);

        default:
            throw new Error("No bill provider configured");
    }

}

// ===============================
// GET BILL ITEMS / PLANS
// ===============================
async function getBillItems(itemCode) {

    switch (ACTIVE_PROVIDER) {

        case "flutterwave":
            return await flutterwave.getBillItems(itemCode);

        default:
            throw new Error("No bill provider configured");
    }

}

// ===============================
// VALIDATE CUSTOMER
// ===============================
async function validateCustomer(itemCode, code, customer) {

    switch (ACTIVE_PROVIDER) {

        case "flutterwave":
            return await flutterwave.validateCustomer(
                itemCode,
                code,
                customer
            );

        default:
            throw new Error("No bill provider configured");
    }

}

module.exports = {

    getCategories,
    getBillItems,
    validateCustomer,

};