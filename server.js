const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// safer DB connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("✅ Database connected"))
  .catch(err => console.log("❌ DB ERROR:", err));

// model
const User = mongoose.model('User', {
  email: String,
  password: String
});

// routes
app.get('/', (req, res) => {
  res.send("CityFive backend is running");
});

app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  await User.create({ email, password });
  res.json({ message: 'User created' });
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email, password });

  if (user) {
    res.json({ message: 'Login success' });
  } else {
    res.status(401).json({ message: 'Invalid details' });
  }
});

// FIXED PORT
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Server running on ' + PORT));
