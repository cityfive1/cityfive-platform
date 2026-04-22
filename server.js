const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');

const app = express();

app.use(cors());
app.use(express.json());

// TEST ROUTE
app.get('/', (req, res) => {
  res.send("CityFive backend is running");
});

// CONNECT DB
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("DB connected"))
  .catch(err => console.log(err));

// MODEL
const User = mongoose.model('User', {
  email: String,
  password: String
});

// REGISTER
app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  await User.create({ email, password });
  res.json({ message: "User created" });
});

// LOGIN
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email, password });

  if (user) {
    res.json({ message: "Login success" });
  } else {
    res.status(401).json({ message: "Invalid details" });
  }
});

// PORT
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Server running on " + PORT));
