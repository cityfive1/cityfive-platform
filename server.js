const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");

const app = express();

app.use(cors());
app.use(express.json());

app.get("/", (req, res) => {
  res.send("CityFive backend is running");
});

const UserSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },
  passwordHash: {
    type: String,
    required: true
  }
});

const User = mongoose.model("User", UserSchema);

app.post("/register", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        message: "Email and password are required"
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        message: "Password must be at least 8 characters"
      });
    }

    const normalizedEmail = email.toLowerCase().trim();

    const existingUser = await User.findOne({
      email: normalizedEmail
    });

    if (existingUser) {
      return res.status(409).json({
        message: "An account with this email already exists"
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    await User.create({
      email: normalizedEmail,
      passwordHash
    });

    res.status(201).json({
      message: "Account created successfully"
    });

  } catch (error) {
    console.error("Registration error:", error);

    res.status(500).json({
      message: "Registration failed"
    });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        message: "Email and password are required"
      });
    }

    const normalizedEmail = email.toLowerCase().trim();

    const user = await User.findOne({
      email: normalizedEmail
    });

    if (!user) {
      return res.status(401).json({
        message: "Invalid email or password"
      });
    }

    const validPassword = await bcrypt.compare(
      password,
      user.passwordHash
    );

    if (!validPassword) {
      return res.status(401).json({
        message: "Invalid email or password"
      });
    }

    res.json({
      message: "Login successful"
    });

  } catch (error) {
    console.error("Login error:", error);

    res.status(500).json({
      message: "Login failed"
    });
  }
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, "0.0.0.0", () => {
  console.log("Server running on port " + PORT);
});

mongoose.connect(process.env.MONGO_URI)
  .then(() => {
    console.log("DB connected");
  })
  .catch((error) => {
    console.error("Database connection failed:", error);
  });
