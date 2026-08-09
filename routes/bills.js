const express = require("express");
const router = express.Router();

const auth = require("../middleware/auth");
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
    auth,
    billsController.getBillItems
);

// ===============================
// VALIDATE CUSTOMER
// ===============================
router.post(
    "/validate",
    auth,
    billsController.validateCustomer
);

module.exports = router;