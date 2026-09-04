
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const crypto = require("crypto");

const app = express();

app.set("trust proxy", 1);

const PORT = Number(process.env.PORT) || 3000;

const SESSION_SECRET =
  process.env.SESSION_SECRET ||
  crypto.randomBytes(32).toString("hex");

const FRONTEND_ORIGIN =
  process.env.FRONTEND_ORIGIN ||
  "https://cityfive1.github.io";

const PLATFORM_MODE =
  process.env.PLATFORM_MODE || "SANDBOX";

const REAL_FUNDS_ENABLED = false;

app.use(
  cors({
    origin: FRONTEND_ORIGIN,
    credentials: true
  })
);

app.use(express.json({ limit: "1mb" }));

app.use(
  session({
    name: "cityfive.sid",
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: 1000 * 60 * 60 * 24
    }
  })
);

/* =========================
   DATABASE MODELS
========================= */

const UserSchema = new mongoose.Schema(
  {
    name: String,
    email: {
      type: String,
      unique: true,
      lowercase: true,
      trim: true
    },
    passwordHash: String,
    role: {
      type: String,
      default: "user"
    },
    accountStatus: {
      type: String,
      default: "pending"
    },
    kycStatus: {
      type: String,
      default: "not_started"
    }
  },
  { timestamps: true }
);

const AccountSchema = new mongoose.Schema(
  {
    userId: mongoose.Schema.Types.ObjectId,
    currency: String,
    available: {
      type: Number,
      default: 0
    },
    pending: {
      type: Number,
      default: 0
    }
  },
  { timestamps: true }
);

const LedgerEntrySchema = new mongoose.Schema(
  {
    userId: mongoose.Schema.Types.ObjectId,
    currency: String,
    type: String,
    amount: Number,
    description: String,
    reference: String
  },
  { timestamps: true }
);

const DepositSchema = new mongoose.Schema(
  {
    userId: mongoose.Schema.Types.ObjectId,
    asset: String,
    amount: Number,
    status: String,
    network: String,
    address: String,
    reference: String
  },
  { timestamps: true }
);

const WithdrawalSchema = new mongoose.Schema(
  {
    userId: mongoose.Schema.Types.ObjectId,
    asset: String,
    amount: Number,
    address: String,
    status: String,
    network: String,
    reference: String
  },
  { timestamps: true }
);

const TradeSchema = new mongoose.Schema(
  {
    userId: mongoose.Schema.Types.ObjectId,
    asset: String,
    side: String,
    amount: Number,
    price: Number,
    status: String
  },
  { timestamps: true }
);

const KycProfileSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      unique: true
    },
    status: {
      type: String,
      default: "not_started"
    },
    country: String
  },
  { timestamps: true }
);

const AuditLogSchema = new mongoose.Schema(
  {
    userId: mongoose.Schema.Types.ObjectId,
    action: String,
    details: String
  },
  { timestamps: true }
);

const User = mongoose.model("User", UserSchema);
const Account = mongoose.model("Account", AccountSchema);
const LedgerEntry = mongoose.model(
  "LedgerEntry",
  LedgerEntrySchema
);
const Deposit = mongoose.model(
  "Deposit",
  DepositSchema
);
const Withdrawal = mongoose.model(
  "Withdrawal",
  WithdrawalSchema
);
const Trade = mongoose.model(
  "Trade",
  TradeSchema
);
const KycProfile = mongoose.model(
  "KycProfile",
  KycProfileSchema
);
const AuditLog = mongoose.model(
  "AuditLog",
  AuditLogSchema
);

/* =========================
   BASIC ROUTES
========================= */

app.get("/", (req, res) => {
  res.json({
    service: "CityFive Holdings Ltd",
    status: "online",
    mode: PLATFORM_MODE,
    realFundsEnabled: REAL_FUNDS_ENABLED
  });
});

app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    mode: PLATFORM_MODE,
    realFundsEnabled: REAL_FUNDS_ENABLED,
    database:
      mongoose.connection.readyState === 1
        ? "connected"
        : "disconnected"
  });
});

/* =========================
   AUTH HELPERS
========================= */

function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({
      error: "Login required"
    });
  }

  next();
}

async function getCurrentUser(req) {
  if (!req.session.userId) {
    return null;
  }

  return User.findById(req.session.userId);
}

async function requireAdmin(req, res, next) {
  const user = await getCurrentUser(req);

  if (!user || user.role !== "admin") {
    return res.status(403).json({
      error: "Admin access required"
    });
  }

  req.currentUser = user;
  next();
}

/* =========================
   REGISTER
========================= */

app.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        error: "Name, email and password are required"
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        error: "Password must contain at least 8 characters"
      });
    }

    const normalizedEmail =
      email.trim().toLowerCase();

    const existing = await User.findOne({
      email: normalizedEmail
    });

    if (existing) {
      return res.status(409).json({
        error: "An account with this email already exists"
      });
    }

    const passwordHash =
      await bcrypt.hash(password, 12);

    const user = await User.create({
      name: name.trim(),
      email: normalizedEmail,
      passwordHash,
      role: "user",
      accountStatus: "pending",
      kycStatus: "not_started"
    });

    await Account.create([
      {
        userId: user._id,
        currency: "USD",
        available: 0,
        pending: 0
      },
      {
        userId: user._id,
        currency: "BTC",
        available: 0,
        pending: 0
      }
    ]);

    await KycProfile.create({
      userId: user._id,
      status: "not_started"
    });

    await AuditLog.create({
      userId: user._id,
      action: "REGISTER",
      details: "User account created"
    });

    res.status(201).json({
      message: "Account created",
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        accountStatus: user.accountStatus,
        kycStatus: user.kycStatus
      }
    });
  } catch (error) {
    console.error("Register error:", error);

    res.status(500).json({
      error: "Registration failed"
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
        error: "Email and password are required"
      });
    }

    const user = await User.findOne({
      email: email.trim().toLowerCase()
    });

    if (!user) {
      return res.status(401).json({
        error: "Invalid email or password"
      });
    }

    const valid =
      await bcrypt.compare(
        password,
        user.passwordHash
      );

    if (!valid) {
      return res.status(401).json({
        error: "Invalid email or password"
      });
    }

    req.session.userId = user._id.toString();

    await AuditLog.create({
      userId: user._id,
      action: "LOGIN",
      details: "User logged in"
    });

    res.json({
      message: "Login successful",
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        accountStatus: user.accountStatus,
        kycStatus: user.kycStatus
      }
    });
  } catch (error) {
    console.error("Login error:", error);

    res.status(500).json({
      error: "Login failed"
    });
  }
});

/* =========================
   CURRENT USER
========================= */

app.get("/me", requireLogin, async (req, res) => {
  try {
    const user = await User.findById(
      req.session.userId
    );

    if (!user) {
      return res.status(401).json({
        error: "User not found"
      });
    }

    const accounts = await Account.find({
      userId: user._id
    });

    res.json({
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        accountStatus: user.accountStatus,
        kycStatus: user.kycStatus
      },
      accounts,
      mode: PLATFORM_MODE,
      realFundsEnabled: REAL_FUNDS_ENABLED
    });
  } catch (error) {
    console.error("Me error:", error);

    res.status(500).json({
      error: "Unable to load account"
    });
  }
});

/* =========================
   KYC
========================= */

app.post(
  "/kyc/start",
  requireLogin,
  async (req, res) => {
    try {
      const profile =
        await KycProfile.findOneAndUpdate(
          { userId: req.session.userId },
          {
            status: "pending"
          },
          {
            new: true,
            upsert: true
          }
        );

      await User.findByIdAndUpdate(
        req.session.userId,
        {
          kycStatus: "pending"
        }
      );

      await AuditLog.create({
        userId: req.session.userId,
        action: "KYC_START",
        details: "Sandbox KYC application started"
      });

      res.json({
        message: "KYC application submitted",
        status: profile.status,
        mode: "SANDBOX"
      });
    } catch (error) {
      console.error("KYC error:", error);

      res.status(500).json({
        error: "Unable to start KYC"
      });
    }
  }
);

/* =========================
   BTC DEPOSIT
========================= */

app.post(
  "/deposits/btc",
  requireLogin,
  async (req, res) => {
    try {
      const user =
        await User.findById(req.session.userId);

      if (!user) {
        return res.status(401).json({
          error: "User not found"
        });
      }

      if (user.kycStatus !== "approved") {
        return res.status(403).json({
          error: "KYC approval required"
        });
      }

      const amount = Number(req.body.amount);

      if (!amount || amount <= 0) {
        return res.status(400).json({
          error: "Enter a valid BTC amount"
        });
      }

      if (PLATFORM_MODE !== "SANDBOX") {
        return res.status(503).json({
          error: "Real BTC deposits are not enabled"
        });
      }

      const reference =
        "DEMO-" +
        crypto.randomBytes(6).toString("hex");

      const deposit =
        await Deposit.create({
          userId: user._id,
          asset: "BTC",
          amount,
          status: "sandbox_pending",
          network: "SANDBOX",
          address: null,
          reference
        });

      await AuditLog.create({
        userId: user._id,
        action: "BTC_DEPOSIT_REQUEST",
        details:
          "Sandbox BTC deposit created: " +
          reference
      });

      res.status(201).json({
        message:
          "Sandbox deposit created. No real Bitcoin was transferred.",
        deposit
      });
    } catch (error) {
      console.error("Deposit error:", error);

      res.status(500).json({
        error: "Unable to create deposit"
      });
    }
  }
);

/* =========================
   BTC WITHDRAWAL
========================= */

app.post(
  "/withdrawals/btc",
  requireLogin,
  async (req, res) => {
    try {
      const user =
        await User.findById(req.session.userId);

      if (!user) {
        return res.status(401).json({
          error: "User not found"
        });
      }

      if (user.kycStatus !== "approved") {
        return res.status(403).json({
          error: "KYC approval required"
        });
      }

      const amount = Number(req.body.amount);
      const address = req.body.address;

      if (!amount || amount <= 0) {
        return res.status(400).json({
          error: "Enter a valid BTC amount"
        });
      }

      if (!address) {
        return res.status(400).json({
          error: "Bitcoin address is required"
        });
      }

      const account =
        await Account.findOne({
          userId: user._id,
          currency: "BTC"
        });

      if (!account || account.available < amount) {
        return res.status(400).json({
          error: "Insufficient BTC balance"
        });
      }

      const reference =
        "DEMO-" +
        crypto.randomBytes(6).toString("hex");

      const withdrawal =
        await Withdrawal.create({
          userId: user._id,
          asset: "BTC",
          amount,
          address,
          status: "under_review",
          network: "SANDBOX",
          reference
        });

      await AuditLog.create({
        userId: user._id,
        action: "BTC_WITHDRAWAL_REQUEST",
        details:
          "Sandbox withdrawal created: " +
          reference
      });

      res.status(201).json({
        message:
          "Sandbox withdrawal submitted for review. No real Bitcoin was sent.",
        withdrawal
      });
    } catch (error) {
      console.error("Withdrawal error:", error);

      res.status(500).json({
        error: "Unable to create withdrawal"
      });
    }
  }
);

/* =========================
   TRANSACTIONS
========================= */

app.get(
  "/transactions",
  requireLogin,
  async (req, res) => {
    try {
      const userId = req.session.userId;

      const [
        ledger,
        deposits,
        withdrawals,
        trades
      ] = await Promise.all([
        LedgerEntry.find({ userId }).sort({
          createdAt: -1
        }),
        Deposit.find({ userId }).sort({
          createdAt: -1
        }),
        Withdrawal.find({ userId }).sort({
          createdAt: -1
        }),
        Trade.find({ userId }).sort({
          createdAt: -1
        })
      ]);

      res.json({
        ledger,
        deposits,
        withdrawals,
        trades
      });
    } catch (error) {
      console.error("Transactions error:", error);

      res.status(500).json({
        error: "Unable to load transactions"
      });
    }
  }
);

/* =========================
   ACCOUNTS
========================= */

app.get(
  "/accounts",
  requireLogin,
  async (req, res) => {
    try {
      const accounts =
        await Account.find({
          userId: req.session.userId
        });

      res.json({
        accounts
      });
    } catch (error) {
      console.error("Accounts error:", error);

      res.status(500).json({
        error: "Unable to load accounts"
      });
    }
  }
);

/* =========================
   ADMIN STATUS
========================= */

app.get(
  "/admin/status",
  requireAdmin,
  async (req, res) => {
    res.json({
      platformMode: PLATFORM_MODE,
      realFundsEnabled: false,
      custodyProviderConnected: false,
      kycProviderConnected: false,
      bitcoinNetwork: "SANDBOX",
      message:
        "Real-money and real-Bitcoin functionality is disabled."
    });
  }
);

/* =========================
   ADMIN USERS
========================= */

app.get(
  "/admin/users",
  requireAdmin,
  async (req, res) => {
    try {
      const users =
        await User.find()
          .select("-passwordHash")
          .sort({ createdAt: -1 });

      res.json({
        users
      });
    } catch (error) {
      console.error("Admin users error:", error);

      res.status(500).json({
        error: "Unable to load users"
      });
    }
  }
);

/* =========================
   ADMIN KYC
========================= */

app.get(
  "/admin/kyc",
  requireAdmin,
  async (req, res) => {
    try {
      const profiles =
        await KycProfile.find()
          .sort({ createdAt: -1 });

      res.json({
        profiles
      });
    } catch (error) {
      console.error("Admin KYC error:", error);

      res.status(500).json({
        error: "Unable to load KYC records"
      });
    }
  }
);

app.post(
  "/admin/kyc/:id/approve",
  requireAdmin,
  async (req, res) => {
    try {
      const profile =
        await KycProfile.findByIdAndUpdate(
          req.params.id,
          {
            status: "approved"
          },
          {
            new: true
          }
        );

      if (!profile) {
        return res.status(404).json({
          error: "KYC profile not found"
        });
      }

      await User.findByIdAndUpdate(
        profile.userId,
        {
          kycStatus: "approved",
          accountStatus: "active"
        }
      );

      await AuditLog.create({
        userId: profile.userId,
        action: "KYC_APPROVED",
        details:
          "KYC approved by administrator"
      });

      res.json({
        message: "KYC approved",
        profile
      });
    } catch (error) {
      console.error("Approve KYC error:", error);

      res.status(500).json({
        error: "Unable to approve KYC"
      });
    }
  }
);

/* =========================
   ADMIN WITHDRAWALS
========================= */

app.get(
  "/admin/withdrawals",
  requireAdmin,
  async (req, res) => {
    try {
      const withdrawals =
        await Withdrawal.find()
          .sort({ createdAt: -1 });

      res.json({
        withdrawals
      });
    } catch (error) {
      console.error(
        "Admin withdrawals error:",
        error
      );

      res.status(500).json({
        error: "Unable to load withdrawals"
      });
    }
  }
);

/* =========================
   AUDIT LOGS
========================= */

app.get(
  "/admin/audit",
  requireAdmin,
  async (req, res) => {
    try {
      const logs =
        await AuditLog.find()
          .sort({ createdAt: -1 })
          .limit(500);

      res.json({
        logs
      });
    } catch (error) {
      console.error("Audit error:", error);

      res.status(500).json({
        error: "Unable to load audit logs"
      });
    }
  }
);

/* =========================
   LOGOUT
========================= */

app.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({
      message: "Logged out"
    });
  });
});

/* =========================
   START SERVER
========================= */

async function startServer() {
  if (!process.env.MONGO_URI) {
    console.error(
      "ERROR: MONGO_URI environment variable is missing."
    );
    process.exit(1);
  }

  const server = app.listen(
    PORT,
    "0.0.0.0",
    () => {
      console.log(
        "Server running on port " + PORT
      );

      console.log(
        "Platform mode: " + PLATFORM_MODE
      );

      console.log(
        "Real funds enabled: false"
      );

      connectDatabase();
    }
  );

  server.on("error", (error) => {
    console.error(
      "HTTP server error:",
      error
    );

    process.exit(1);
  });

  async function connectDatabase() {
    try {
      await mongoose.connect(
        process.env.MONGO_URI
      );

      console.log("DB connected");
    } catch (error) {
      console.error(
        "Database connection error:",
        error
      );
    }
  }

  async function shutdown(signal) {
    console.log(
      signal +
        " received. Shutting down gracefully..."
    );

    server.close(async () => {
      try {
        await mongoose.connection.close();

        console.log(
          "Database connection closed."
        );
      } catch (error) {
        console.error(
          "Error closing database:",
          error
        );
      }

      process.exit(0);
    });

    setTimeout(() => {
      console.error(
        "Forced shutdown after timeout."
      );

      process.exit(1);
    }, 10000).unref();
  }

  process.on("SIGTERM", () =>
    shutdown("SIGTERM")
  );

  process.on("SIGINT", () =>
    shutdown("SIGINT")
  );
}

startServer();
