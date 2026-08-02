const billEngine = require("../services/billEngine");

// ======================================
// GET BILL CATEGORIES
// ======================================
exports.getCategories = async (req, res) => {

    try {

        const { type } = req.query;

        const data = await billEngine.getCategories(type);

        res.json({
            success: true,
            categories: data
        });

    } catch (err) {

        console.error(err.message);

        res.status(500).json({
            success: false,
            error: err.message
        });

    }

};

// ======================================
// GET BILL ITEMS / PACKAGES
// ======================================
exports.getBillItems = async (req, res) => {

    try {

        const { item_code } = req.body;

        if (!item_code) {

            return res.status(400).json({
                success: false,
                error: "item_code is required"
            });

        }

        const data = await billEngine.getBillItems(item_code);

        res.json({
            success: true,
            items: data
        });

    } catch (err) {

        console.error(err.message);

        res.status(500).json({
            success: false,
            error: err.message
        });

    }

};

// ======================================
// VALIDATE CUSTOMER
// ======================================
exports.validateCustomer = async (req, res) => {

    try {

        const { item_code, code, customer } = req.body;

        if (!item_code || !code || !customer) {

            return res.status(400).json({
                success: false,
                error: "item_code, code and customer are required"
            });

        }

        const data = await billEngine.validateCustomer(
            item_code,
            code,
            customer
        );

        res.json({
            success: true,
            customerDetails: data
        });

    } catch (err) {

        console.error(err.message);

        res.status(500).json({
            success: false,
            error: err.message
        });

    }

};