const express = require("express");
const dotenv = require("dotenv");
dotenv.config();
const router = express.Router();
router.post("/logout", (req, res) => {
    // Log incoming cookies (must be enabled in your middleware)
    console.log("Cookies received with the request:", req.cookies);

    if (req.cookies && req.cookies.refreshToken) {
        console.log("Refresh token present:", req.cookies.refreshToken);
    } else {
        console.log("No refresh token found in the cookies.");
    }

    // Clear the refresh token cookie
    res.clearCookie("refreshToken", {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
    });

    console.log("Cookies being sent after logout:", res.getHeaders()["set-cookie"]);

    res.status(200).json({ message: "Logout successful" });
});
module.exports = router;
