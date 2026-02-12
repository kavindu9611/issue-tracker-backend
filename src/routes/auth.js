const express = require('express');
const { register, verifyOtp, login, forgotPassword, resetPassword } = require('../controllers/auth');
const protect = require('../middleware/auth');

const router = express.Router();

router.post('/register', register);
router.post('/verify-otp', verifyOtp);
router.post('/login', login);
router.post('/forgot-password', forgotPassword);
router.post('/reset-password', resetPassword);

// Example protected route (for future issues)
router.get('/protected', protect, (req, res) => {
  res.json({ message: 'Protected route accessed', userId: req.user.id });
});

module.exports = router;