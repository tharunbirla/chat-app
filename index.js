const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.use(express.json());

// MongoDB Connection
const dbURI = process.env.MONGO_URI;
mongoose.connect(dbURI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => console.log('Failed to connect to MongoDB', err));

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  password: String,
  dob: Date,
});

const User = mongoose.model('User', userSchema);

// Register Endpoint
app.post('/register', async (req, res) => {
  const { username, password, dob } = req.body;

  // Check if the user already exists
  const userExist = await User.findOne({ username });
  if (userExist) {
    return res.status(400).send('User already exists');
  }

  // Check if the user is 18 or older
  const age = new Date().getFullYear() - new Date(dob).getFullYear();
  if (age < 18) {
    return res.status(400).send('Must be 18+ to register');
  }

  // Hash the password
  const hashedPassword = await bcrypt.hash(password, 10);

  // Create new user and save to the database
  const newUser = new User({ username, password: hashedPassword, dob });

  try {
    await newUser.save();
    res.status(201).send('User created');
  } catch (err) {
    console.error('Error creating user:', err);
    res.status(500).send('Error creating user');
  }
});

// Login Endpoint
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  // Check if the user exists
  const user = await User.findOne({ username });
  if (!user) {
    return res.status(400).send('User not found');
  }

  // Compare the password
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.status(400).send('Invalid password');
  }

  // Generate a JWT token
  const token = jwt.sign({ username }, process.env.JWT_SECRET, { expiresIn: '1h' });

  // Send back the token
  res.json({ token });
});

// Start the Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
