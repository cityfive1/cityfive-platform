const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const session = require("express-session");

const app = express();

app.set("trust proxy", 1);

app.use(cors({
origin: "https://cityfive1.github.io",
credentials: true
}));

app.use(express.json());

app.use(session({
name: "cityfive.sid",
secret: process.env.SESSION_SECRET,
resave: false,
saveUninitialized: false,
cookie: {
httpOnly: true,
secure: true,
sameSite: "none",
maxAge: 1000 * 60 * 60 * 24
}
}));

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

req.session.userId = user._id.toString();

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

function requireLogin(req, res, next) {
if (!req.session.userId) {
return res.status(401).json({
message: "Authentication required"
});
}

next();
}

app.get("/me", requireLogin, async (req, res) => {
try {
const user = await User.findById(req.session.userId)
.select("email");

if (!user) {
  req.session.destroy(() => {});

  return res.status(401).json({
    message: "User not found"
  });
}

res.json({
  email: user.email
});

} catch (error) {
console.error("Profile error:", error);

res.status(500).json({
  message: "Unable to load account"
});

}
});

app.post("/logout", (req, res) => {
req.session.destroy((error) => {
if (error) {
return res.status(500).json({
message: "Logout failed"
});
}

res.clearCookie("cityfive.sid");

res.json({
  message: "Logged out successfully"
});

});
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
