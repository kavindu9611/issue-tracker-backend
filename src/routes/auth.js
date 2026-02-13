const express = require('express');
const { register,login} = require('../controllers/auth');
const protect = require('../middleware/auth');

const router = express.Router();

router.post('/register', register);
router.post('/login', login);


router.get('/protected', protect, (req, res) => {
  res.json({ message: 'Protected route accessed', userId: req.user.id });
});

module.exports = router;