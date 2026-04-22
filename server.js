const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');

const app = express();

// ✅ CORS (simple + safe)
app.use(cors({
  origin: "*"
}));

app.use(express.json());

// ✅ ROOT ROUTE (VERY IMPORTANT)
app.get('/', (req, res) => {
  res.send("CityFive backend is running");
});

// ✅ CONNECT DATABASE
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("DB connected"))
  .catch(err => console.log(err));

// ✅ MODEL
const User = mongoose.model('User', {
  email: String,
  password: String
});

// ✅ REGISTER
app.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    await User.create({ email, password });
    res.json({ message: 'User created' });
  } catch (err) {
    res.status(500).json({ message: 'Error creating user' });
  }
});

// ✅ LOGIN
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email, password });

    if (user) {
      res.json({ message: 'Login success' });
    } else {
      res.status(401).json({ message: 'Invalid details' });
    }
  } catch (err) {
    res.status(500).json({ message: 'Login error' });
  }
});

// ✅ PORT FIX (VERY IMPORTANT)
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Server running on " + PORT));
