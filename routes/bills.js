const express = require("express");
const router = express.Router();

//const auth = require("../middleware/auth");
const billsController = require("../controllers/billsController");

// ===============================
// GET BILL CATEGORIES
// ===============================
router.get(
    "/categories",
    auth,
    billsController.getCategories
);

// ===============================
// GET BILL ITEMS / PACKAGES
// ===============================
router.post(
    "/items",
    
    billsController.getBillItems
);

// ADD THESE 3 NEW ONES
// VALIDATE METER/SMARTCARD
router.post("/validate",  billsController.validateBill);

// PAY ELECTRICITY/CABLE
router.post("/pay", billsController.payBill);

// GET ALL VTPASS SERVICES FOR MORE SCREEN
router.get("/vtpass-services", auth, billsController.getVtpassServices);

// PAY JAMB/WAEC/BETTING ETC
router.post("/vtpass-pay",  billsController.payVtpass);

// ===============================
// VALIDATE CUSTOMER
// ===============================
router.post(
    "/validate",

    billsController.validateCustomer
);

module.exports = router;