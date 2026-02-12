const User = require('../models/User');
const jwt = require('jsonwebtoken');
const sendEmail = require('../utils/sendEmail');
const dotenv = require('dotenv');

dotenv.config();

const generateOtp = () => Math.floor(100000 + Math.random() * 900000).toString();

const register = async (req, res) => {
  const { fullName, email, password, confirmPassword } = req.body;
  if (password !== confirmPassword) return res.status(400).json({ message: 'Passwords do not match' });

  const userExists = await User.findOne({ email });
  if (userExists) return res.status(400).json({ message: 'User already exists' });
  console.log("user12", req.body)
  const user = new User({ fullName, email, password });
  
  const otp = generateOtp();
  user.otp = otp;
  user.otpExpiry = Date.now() + 10 * 60 * 1000;
  console.log("user12 after after", req.body)

  await user.save();

  await sendEmail(email, 'Verify Your Email', `Your OTP is: ${otp}`);

  res.status(201).json({ message: 'User registered. OTP sent to email.' });
};

const verifyOtp = async (req, res) => {
  const { email, otp } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ message: 'User not found' });

  if (user.otp !== otp || user.otpExpiry < Date.now()) {
    return res.status(400).json({ message: 'Invalid or expired OTP' });
  }

  user.isVerified = true;
  user.otp = undefined;
  user.otpExpiry = undefined;
  await user.save();

  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
  res.json({ token, user: { id: user._id, fullName: user.fullName, email: user.email } });
};

const login = async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user || !user.isVerified) return res.status(400).json({ message: 'Invalid credentials or unverified email' });

  const isMatch = await user.comparePassword(password);
  if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
  res.json({ token, user: { id: user._id, fullName: user.fullName, email: user.email } });
};

const forgotPassword = async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ message: 'User not found' });

  const otp = generateOtp();
  user.resetOtp = otp;
  user.resetOtpExpiry = Date.now() + 10 * 60 * 1000; // 10 min
  await user.save();

  await sendEmail(email, 'Reset Your Password', `Your reset OTP is: ${otp}`);

  res.json({ message: 'Reset OTP sent to email' });
};

const resetPassword = async (req, res) => {
  const { email, otp, newPassword, confirmNewPassword } = req.body;
  if (newPassword !== confirmNewPassword) return res.status(400).json({ message: 'Passwords do not match' });

  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ message: 'User not found' });

  if (user.resetOtp !== otp || user.resetOtpExpiry < Date.now()) {
    return res.status(400).json({ message: 'Invalid or expired OTP' });
  }

  user.password = newPassword;
  user.resetOtp = undefined;
  user.resetOtpExpiry = undefined;
  await user.save();

  res.json({ message: 'Password reset successful' });
};

module.exports = { register, verifyOtp, login, forgotPassword, resetPassword };