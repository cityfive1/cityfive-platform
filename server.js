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


/* =========================
HOME
========================= */

app.get("/", (req, res) => {
  res.send("CityFive backend is running");
});


/* =========================
USER MODEL
========================= */

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
  },

  usdBalance: {
    type: Number,
    default: 0,
    min: 0
  },

  btcBalance: {
    type: Number,
    default: 0,
    min: 0
  },

  createdAt: {
    type: Date,
    default: Date.now
  }
});

const User = mongoose.model("User", UserSchema);


/* =========================
TRANSACTION MODEL
========================= */

const TransactionSchema = new mongoose.Schema({

  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
    index: true
  },

  type: {
    type: String,
    enum: [
      "deposit",
      "withdrawal",
      "btc_purchase",
      "btc_sale",
      "investment"
    ],
    required: true
  },

  asset: {
    type: String,
    enum: ["USD", "BTC"],
    required: true
  },

  amount: {
    type: Number,
    required: true,
    min: 0
  },

  status: {
    type: String,
    enum: [
      "pending",
      "completed",
      "failed",
      "cancelled"
    ],
    default: "pending"
  },

  reference: {
    type: String,
    unique: true,
    sparse: true
  },

  description: {
    type: String,
    default: ""
  },

  createdAt: {
    type: Date,
    default: Date.now
  }

});

const Transaction =
  mongoose.model("Transaction", TransactionSchema);


/* =========================
REGISTER
========================= */

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

    const normalizedEmail =
      email.toLowerCase().trim();

    const existingUser =
      await User.findOne({
        email: normalizedEmail
      });

    if (existingUser) {
      return res.status(409).json({
        message: "An account with this email already exists"
      });
    }

    const passwordHash =
      await bcrypt.hash(password, 12);

    await User.create({
      email: normalizedEmail,
      passwordHash
    });

    res.status(201).json({
      message: "Account created successfully"
    });

  } catch (error) {

    console.error(
      "Registration error:",
      error
    );

    res.status(500).json({
      message: "Registration failed"
    });

  }

});


/* =========================
LOGIN
========================= */

app.post("/login", async (req, res) => {

  try {

    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        message: "Email and password are required"
      });
    }

    const normalizedEmail =
      email.toLowerCase().trim();

    const user =
      await User.findOne({
        email: normalizedEmail
      });

    if (!user) {
      return res.status(401).json({
        message: "Invalid email or password"
      });
    }

    const validPassword =
      await bcrypt.compare(
        password,
        user.passwordHash
      );

    if (!validPassword) {
      return res.status(401).json({
        message: "Invalid email or password"
      });
    }

    req.session.userId =
      user._id.toString();

    res.json({
      message: "Login successful"
    });

  } catch (error) {

    console.error(
      "Login error:",
      error
    );

    res.status(500).json({
      message: "Login failed"
    });

  }

});


/* =========================
AUTHENTICATION
========================= */

function requireLogin(req, res, next) {

  if (!req.session.userId) {

    return res.status(401).json({
      message: "Authentication required"
    });

  }

  next();

}


/* =========================
CURRENT USER / BALANCE
========================= */

app.get(
  "/me",
  requireLogin,
  async (req, res) => {

    try {

      const user =
        await User.findById(
          req.session.userId
        ).select(
          "email usdBalance btcBalance createdAt"
        );

      if (!user) {

        req.session.destroy(() => {});

        return res.status(401).json({
          message: "User not found"
        });

      }

      res.json({
        email: user.email,
        usdBalance: user.usdBalance,
        btcBalance: user.btcBalance,
        createdAt: user.createdAt
      });

    } catch (error) {

      console.error(
        "Profile error:",
        error
      );

      res.status(500).json({
        message: "Unable to load account"
      });

    }

  }
);


/* =========================
USER TRANSACTIONS
========================= */

app.get(
  "/transactions",
  requireLogin,
  async (req, res) => {

    try {

      const transactions =
        await Transaction.find({
          userId: req.session.userId
        })
        .sort({
          createdAt: -1
        })
        .limit(100);

      res.json({
        transactions
      });

    } catch (error) {

      console.error(
        "Transaction error:",
        error
      );

      res.status(500).json({
        message:
          "Unable to load transactions"
      });

    }

  }
);


/* =========================
SIMULATED DEMO DATA
========================= */

app.post(
  "/demo-data",
  requireLogin,
  async (req, res) => {

    try {

      const user =
        await User.findById(
          req.session.userId
        );

      if (!user) {

        return res.status(404).json({
          message: "User not found"
        });

      }


      /*
        DEMO ONLY.

        These values are simulated.
        They are NOT real money,
        real Bitcoin, or real investment returns.
      */

      user.usdBalance = 10000;
      user.btcBalance = 0.125;

      await user.save();


      /* Remove previous demo transactions */

      await Transaction.deleteMany({
        userId: user._id,
        reference: {
          $regex: /^DEMO-/
        }
      });


      /* Create simulated history */

      await Transaction.insertMany([

        {
          userId: user._id,
          type: "deposit",
          asset: "USD",
          amount: 10000,
          status: "completed",
          reference: "DEMO-DEPOSIT-001",
          description:
            "Simulated demo deposit"
        },

        {
          userId: user._id,
          type: "investment",
          asset: "USD",
          amount: 5000,
          status: "completed",
          reference: "DEMO-INVESTMENT-001",
          description:
            "Simulated demo investment"
        },

        {
          userId: user._id,
          type: "btc_purchase",
          asset: "BTC",
          amount: 0.125,
          status: "completed",
          reference: "DEMO-BTC-001",
          description:
            "Simulated Bitcoin purchase"
        },

        {
          userId: user._id,
          type: "investment",
          asset: "USD",
          amount: 750,
          status: "completed",
          reference: "DEMO-PROFIT-001",
          description:
            "Simulated investment return"
        }

      ]);


      res.json({
        message:
          "Demo data created successfully",
        simulated: true
      });

    } catch (error) {

      console.error(
        "Demo data error:",
        error
      );

      res.status(500).json({
        message:
          "Unable to create demo data"
      });

    }

  }
);


/* =========================
LOGOUT
========================= */

app.post(
  "/logout",
  (req, res) => {

    req.session.destroy(
      (error) => {

        if (error) {

          return res.status(500).json({
            message: "Logout failed"
          });

        }

        res.clearCookie(
          "cityfive.sid"
        );

        res.json({
          message:
            "Logged out successfully"
        });

      }
    );

  }
);


/* =========================
SERVER
========================= */

const PORT =
  process.env.PORT || 3000;

app.listen(
  PORT,
  "0.0.0.0",
  () => {

    console.log(
      "Server running on port " + PORT
    );

  }
);


/* =========================
DATABASE
========================= */

mongoose.connect(
  process.env.MONGO_URI
)
.then(() => {

  console.log("DB connected");

})
.catch((error) => {

  console.error(
    "Database connection failed:",
    error
  );

});
