const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// connect DB
mongoose.connect(process.env.MONGO_URI);

// user model
const User = mongoose.model('User', {
  email: String,
  password: String
});

// register
app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  await User.create({ email, password });
  res.json({ message: 'User created' });
});

// login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email, password });

  if (user) {
    res.json({ message: 'Login success' });
  } else {
    res.status(401).json({ message: 'Invalid details' });
  }
});

app.listen(3000, () => console.log('Server running'));
