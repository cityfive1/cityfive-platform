
const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const OpenAI = require("openai");

const app = express();

const PORT = Number(process.env.PORT || 3000);

const MONGO_URI = process.env.MONGO_URI;
const FRONTEND_ORIGIN =
  process.env.FRONTEND_ORIGIN ||
  "https://cityfive1.github.io";

const SESSION_SECRET = process.env.SESSION_SECRET;

const PLATFORM_MODE =
  process.env.PLATFORM_MODE || "SANDBOX";

const REAL_FUNDS_ENABLED =
  String(process.env.REAL_FUNDS_ENABLED).toLowerCase() === "true";

const SANDBOX_RESET_KEY =
  process.env.SANDBOX_RESET_KEY;

const OPENAI_API_KEY =
  process.env.OPENAI_API_KEY;

const OPENAI_MODEL =
  process.env.OPENAI_MODEL || "gpt-5.5";

if (!MONGO_URI) {
  throw new Error("MONGO_URI is required");
}

if (!SESSION_SECRET) {
  throw new Error("SESSION_SECRET is required");
}

if (PLATFORM_MODE !== "SANDBOX") {
  throw new Error(
    "This version of CityFive is SANDBOX-only."
  );
}

if (REAL_FUNDS_ENABLED) {
  throw new Error(
    "REAL_FUNDS_ENABLED must remain false in SANDBOX mode."
  );
}

app.use(
  cors({
    origin: [
      FRONTEND_ORIGIN,
      "https://cityfive1.github.io",
      "http://localhost:3000",
      "http://127.0.0.1:3000"
    ],
    credentials: false
  })
);

app.use(
  express.json({
    limit: "1mb"
  })
);

app.use(
  express.urlencoded({
    extended: true
  })
);

function sha256(value) {
  return crypto
    .createHash("sha256")
    .update(String(value))
    .digest("hex");
}

function randomToken(bytes = 32) {
  return crypto
    .randomBytes(bytes)
    .toString("hex");
}

function publicUser(user) {
  return {
    id: String(user._id),
    name: user.name,
    email: user.email,
    role: user.role,
    createdAt: user.createdAt
  };
}

async function audit(
  action,
  userId = null,
  metadata = {}
) {
  try {
    await Audit.create({
      action,
      userId,
      metadata
    });
  } catch (error) {
    console.error(
      "Audit error:",
      error.message
    );
  }
}

async function issueToken(user) {
  const rawToken = randomToken(32);

  const tokenHash = sha256(rawToken);

  await AuthToken.create({
    tokenHash,
    userId: user._id,
    expiresAt: new Date(
      Date.now() +
        1000 *
          60 *
          60 *
          24 *
          30
    )
  });

  return rawToken;
}

function bearer(req) {
  const header =
    req.headers.authorization || "";

  if (
    !header.startsWith(
      "Bearer "
    )
  ) {
    return null;
  }

  return header.slice(7).trim();
}

async function requireAuth(
  req,
  res,
  next
) {
  try {
    const token = bearer(req);

    if (!token) {
      return res.status(401).json({
        error: "Authentication required"
      });
    }

    const tokenHash = sha256(token);

    const authToken =
      await AuthToken.findOne({
        tokenHash
      });

    if (!authToken) {
      return res.status(401).json({
        error: "Invalid session"
      });
    }

    if (
      authToken.expiresAt &&
      authToken.expiresAt < new Date()
    ) {
      await AuthToken.deleteOne({
        _id: authToken._id
      });

      return res.status(401).json({
        error: "Session expired"
      });
    }

    const user =
      await User.findById(
        authToken.userId
      );

    if (!user) {
      return res.status(401).json({
        error: "User not found"
      });
    }

    req.user = user;
    req.authToken = authToken;

    next();
  } catch (error) {
    console.error(
      "Authentication error:",
      error
    );

    return res.status(500).json({
      error: "Authentication failed"
    });
  }
}

async function requireAdmin(
  req,
  res,
  next
) {
  await requireAuth(
    req,
    res,
    () => {
      if (
        req.user.role !==
        "admin"
      ) {
        return res.status(403).json({
          error: "Admin access required"
        });
      }

      next();
    }
  );
}

async function ensureAccounts(
  userId
) {
  let account =
    await Account.findOne({
      userId
    });

  if (!account) {
    account = await Account.create({
      userId,
      currency: "CAD",
      availableBalance: 0,
      pendingBalance: 0
    });
  }

  return account;
}

function validBtcAmount(
  value
) {
  const amount = Number(value);

  if (
    !Number.isFinite(amount) ||
    amount <= 0
  ) {
    return null;
  }

  if (amount > 100) {
    return null;
  }

  return amount;
}

/* =========================
   DATABASE MODELS
========================= */

const userSchema =
  new mongoose.Schema(
    {
      name: {
        type: String,
        required: true,
        trim: true
      },

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

      role: {
        type: String,
        enum: [
          "user",
          "admin"
        ],
        default: "user"
      }
    },
    {
      timestamps: true
    }
  );

const User =
  mongoose.model(
    "User",
    userSchema
  );

const authTokenSchema =
  new mongoose.Schema(
    {
      tokenHash: {
        type: String,
        required: true,
        unique: true
      },

      userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: true
      },

      expiresAt: {
        type: Date,
        required: true
      }
    },
    {
      timestamps: true
    }
  );

const AuthToken =
  mongoose.model(
    "AuthToken",
    authTokenSchema
  );

const passwordResetSchema =
  new mongoose.Schema(
    {
      userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: true
      },

      tokenHash: {
        type: String,
        required: true
      },

      expiresAt: {
        type: Date,
        required: true
      }
    },
    {
      timestamps: true
    }
  );

const PasswordReset =
  mongoose.model(
    "PasswordReset",
    passwordResetSchema
  );

const accountSchema =
  new mongoose.Schema(
    {
      userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        unique: true,
        required: true
      },

      currency: {
        type: String,
        default: "CAD"
      },

      availableBalance: {
        type: Number,
        default: 0
      },

      pendingBalance: {
        type: Number,
        default: 0
      }
    },
    {
      timestamps: true
    }
  );

const Account =
  mongoose.model(
    "Account",
    accountSchema
  );

const depositSchema =
  new mongoose.Schema(
    {
      userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: true
      },

      currency: {
        type: String,
        default: "BTC"
      },

      amount: {
        type: Number,
        required: true
      },

      status: {
        type: String,
        enum: [
          "pending",
          "confirmed",
          "cancelled"
        ],
        default: "pending"
      },

      address: {
        type: String,
        default: null
      },

      txid: {
        type: String,
        default: null
      },

      confirmedAt: {
        type: Date,
        default: null
      }
    },
    {
      timestamps: true
    }
  );

const Deposit =
  mongoose.model(
    "Deposit",
    depositSchema
  );

const withdrawalSchema =
  new mongoose.Schema(
    {
      userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: true
      },

      currency: {
        type: String,
        default: "BTC"
      },

      amount: {
        type: Number,
        required: true
      },

      address: {
        type: String,
        required: true
      },

      status: {
        type: String,
        enum: [
          "pending",
          "approved",
          "rejected",
          "completed"
        ],
        default: "pending"
      },

      txid: {
        type: String,
        default: null
      },

      reviewedAt: {
        type: Date,
        default: null
      }
    },
    {
      timestamps: true
    }
  );

const Withdrawal =
  mongoose.model(
    "Withdrawal",
    withdrawalSchema
  );

const ledgerSchema =
  new mongoose.Schema(
    {
      userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: true
      },

      type: {
        type: String,
        required: true
      },

      currency: {
        type: String,
        required: true
      },

      amount: {
        type: Number,
        required: true
      },

      description: {
        type: String,
        default: ""
      },

      referenceId: {
        type: String,
        default: null
      }
    },
    {
      timestamps: true
    }
  );

const Ledger =
  mongoose.model(
    "Ledger",
    ledgerSchema
  );

const kycSchema =
  new mongoose.Schema(
    {
      userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        unique: true,
        required: true
      },

      status: {
        type: String,
        enum: [
          "not_started",
          "pending",
          "approved",
          "rejected"
        ],
        default: "not_started"
      },

      fullName: {
        type: String,
        default: ""
      },

      country: {
        type: String,
        default: ""
      },

      documentType: {
        type: String,
        default: ""
      }
    },
    {
      timestamps: true
    }
  );

const KycProfile =
  mongoose.model(
    "KycProfile",
    kycSchema
  );

const auditSchema =
  new mongoose.Schema(
    {
      action: {
        type: String,
        required: true
      },

      userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        default: null
      },

      metadata: {
        type: mongoose.Schema.Types.Mixed,
        default: {}
      }
    },
    {
      timestamps: true
    }
  );

const Audit =
  mongoose.model(
    "Audit",
    auditSchema
  );

/* =========================
   PUBLIC ROUTES
========================= */

app.get(
  "/",
  (req, res) => {
    res.json({
      service:
        "CityFive Holdings Ltd",
      status: "online",
      mode: "SANDBOX",
      realFundsEnabled: false
    });
  }
);

app.get(
  "/health",
  (req, res) => {
    res.json({
      status: "ok",
      service:
        "CityFive Holdings Ltd",
      mode: "SANDBOX",
      realFundsEnabled: false
    });
  }
);

/* =========================
   AUTH
========================= */

app.post(
  "/register",
  async (req, res) => {
    try {
      const {
        name,
        email,
        password
      } = req.body;

      if (
        !name ||
        !email ||
        !password
      ) {
        return res.status(400).json({
          error:
            "Name, email and password are required"
        });
      }

      if (
        String(password).length < 8
      ) {
        return res.status(400).json({
          error:
            "Password must be at least 8 characters"
        });
      }

      const normalizedEmail =
        String(email)
          .trim()
          .toLowerCase();

      const existing =
        await User.findOne({
          email:
            normalizedEmail
        });

      if (existing) {
        return res.status(409).json({
          error:
            "An account with that email already exists"
        });
      }

      const passwordHash =
        await bcrypt.hash(
          String(password),
          12
        );

      const user =
        await User.create({
          name:
            String(name).trim(),
          email:
            normalizedEmail,
          passwordHash,
          role: "user"
        });

      await ensureAccounts(
        user._id
      );

      await KycProfile.create({
        userId: user._id
      });

      await audit(
        "USER_REGISTERED",
        user._id
      );

      const token =
        await issueToken(user);

      return res.status(201).json({
        user:
          publicUser(user),
        token
      });
    } catch (error) {
      console.error(
        "Register error:",
        error
      );

      return res.status(500).json({
        error:
          "Registration failed"
      });
    }
  }
);

app.post(
  "/login",
  async (req, res) => {
    try {
      const {
        email,
        password
      } = req.body;

      if (
        !email ||
        !password
      ) {
        return res.status(400).json({
          error:
            "Email and password are required"
        });
      }

      const normalizedEmail =
        String(email)
          .trim()
          .toLowerCase();

      const user =
        await User.findOne({
          email:
            normalizedEmail
        });

      if (!user) {
        return res.status(401).json({
          error:
            "Invalid email or password"
        });
      }

      const valid =
        await bcrypt.compare(
          String(password),
          user.passwordHash
        );

      if (!valid) {
        return res.status(401).json({
          error:
            "Invalid email or password"
        });
      }

      await ensureAccounts(
        user._id
      );

      const token =
        await issueToken(user);

      await audit(
        "USER_LOGIN",
        user._id
      );

      return res.json({
        user:
          publicUser(user),
        token
      });
    } catch (error) {
      console.error(
        "Login error:",
        error
      );

      return res.status(500).json({
        error:
          "Login failed"
      });
    }
  }
);

app.get(
  "/me",
  requireAuth,
  async (req, res) => {
    return res.json({
      user:
        publicUser(req.user)
    });
  }
);

/* =========================
   SANDBOX PASSWORD RESET
========================= */

app.post(
  "/sandbox/request-password-reset",
  async (req, res) => {
    try {
      const {
        email,
        sandboxResetKey
      } = req.body;

      if (
        !SANDBOX_RESET_KEY ||
        sandboxResetKey !==
          SANDBOX_RESET_KEY
      ) {
        return res.status(403).json({
          error:
            "Sandbox reset not authorized"
        });
      }

      if (!email) {
        return res.status(400).json({
          error:
            "Email is required"
        });
      }

      const normalizedEmail =
        String(email)
          .trim()
          .toLowerCase();

      const user =
        await User.findOne({
          email:
            normalizedEmail
        });

      if (!user) {
        return res.status(404).json({
          error:
            "User not found"
        });
      }

      const rawToken =
        randomToken(32);

      await PasswordReset.deleteMany({
        userId: user._id
      });

      await PasswordReset.create({
        userId: user._id,
        tokenHash:
          sha256(rawToken),
        expiresAt: new Date(
          Date.now() +
            1000 * 60 * 15
        )
      });

      return res.json({
        message:
          "Sandbox reset token created",
        token: rawToken
      });
    } catch (error) {
      console.error(
        "Password reset request error:",
        error
      );

      return res.status(500).json({
        error:
          "Password reset request failed"
      });
    }
  }
);

app.post(
  "/sandbox/reset-password",
  async (req, res) => {
    try {
      const {
        token,
        newPassword,
        sandboxResetKey
      } = req.body;

      if (
        !SANDBOX_RESET_KEY ||
        sandboxResetKey !==
          SANDBOX_RESET_KEY
      ) {
        return res.status(403).json({
          error:
            "Sandbox reset not authorized"
        });
      }

      if (
        !token ||
        !newPassword
      ) {
        return res.status(400).json({
          error:
            "Token and new password are required"
        });
      }

      if (
        String(newPassword).length < 8
      ) {
        return res.status(400).json({
          error:
            "Password must be at least 8 characters"
        });
      }

      const reset =
        await PasswordReset.findOne({
          tokenHash:
            sha256(token)
        });

      if (!reset) {
        return res.status(400).json({
          error:
            "Invalid reset token"
        });
      }

      if (
        reset.expiresAt < new Date()
      ) {
        await PasswordReset.deleteOne({
          _id: reset._id
        });

        return res.status(400).json({
          error:
            "Reset token expired"
        });
      }

      const passwordHash =
        await bcrypt.hash(
          String(newPassword),
          12
        );

      await User.updateOne(
        {
          _id: reset.userId
        },
        {
          $set: {
            passwordHash
          }
        }
      );

      await AuthToken.deleteMany({
        userId: reset.userId
      });

      await PasswordReset.deleteMany({
        userId: reset.userId
      });

      await audit(
        "PASSWORD_RESET",
        reset.userId
      );

      return res.json({
        message:
          "Password reset successfully"
      });
    } catch (error) {
      console.error(
        "Password reset error:",
        error
      );

      return res.status(500).json({
        error:
          "Password reset failed"
      });
    }
  }
);

/* =========================
   KYC
========================= */

app.get(
  "/kyc",
  requireAuth,
  async (req, res) => {
    try {
      let kyc =
        await KycProfile.findOne({
          userId:
            req.user._id
        });

      if (!kyc) {
        kyc =
          await KycProfile.create({
            userId:
              req.user._id
          });
      }

      return res.json({
        kyc
      });
    } catch (error) {
      console.error(
        "KYC error:",
        error
      );

      return res.status(500).json({
        error:
          "Could not load KYC"
      });
    }
  }
);

app.post(
  "/kyc",
  requireAuth,
  async (req, res) => {
    try {
      const {
        fullName,
        country,
        documentType
      } = req.body;

      const kyc =
        await KycProfile.findOneAndUpdate(
          {
            userId:
              req.user._id
          },
          {
            $set: {
              fullName:
                fullName || "",
              country:
                country || "",
              documentType:
                documentType || "",
              status: "pending"
            }
          },
          {
            new: true,
            upsert: true
          }
        );

      await audit(
        "KYC_UPDATED",
        req.user._id
      );

      return res.json({
        kyc
      });
    } catch (error) {
      console.error(
        "KYC update error:",
        error
      );

      return res.status(500).json({
        error:
          "Could not update KYC"
      });
    }
  }
);

app.post(
  "/kyc/submit",
  requireAuth,
  async (req, res) => {
    try {
      const kyc =
        await KycProfile.findOneAndUpdate(
          {
            userId:
              req.user._id
          },
          {
            $set: {
              status: "pending"
            }
          },
          {
            new: true,
            upsert: true
          }
        );

      await audit(
        "KYC_SUBMITTED",
        req.user._id
      );

      return res.json({
        message:
          "KYC submitted for review",
        kyc
      });
    } catch (error) {
      console.error(
        "KYC submit error:",
        error
      );

      return res.status(500).json({
        error:
          "KYC submission failed"
      });
    }
  }
);

/* =========================
   ACCOUNTS
========================= */

app.get(
  "/accounts",
  requireAuth,
  async (req, res) => {
    try {
      const account =
        await ensureAccounts(
          req.user._id
        );

      return res.json({
        account
      });
    } catch (error) {
      console.error(
        "Account error:",
        error
      );

      return res.status(500).json({
        error:
          "Could not load account"
      });
    }
  }
);

/* =========================
   SANDBOX BTC DEPOSITS
========================= */

app.post(
  "/deposits/btc",
  requireAuth,
  async (req, res) => {
    try {
      const amount =
        validBtcAmount(
          req.body.amount
        );

      if (amount === null) {
        return res.status(400).json({
          error:
            "Invalid BTC amount"
        });
      }

      /*
       * SANDBOX ONLY:
       * This creates a simulated deposit.
       * It does NOT represent a real blockchain payment.
       */

      const deposit =
        await Deposit.create({
          userId:
            req.user._id,
          currency: "BTC",
          amount,
          status: "pending",
          address:
            `SANDBOX-BTC-${randomToken(
              8
            )}`
        });

      await audit(
        "SANDBOX_BTC_DEPOSIT_CREATED",
        req.user._id,
        {
          depositId:
            String(deposit._id),
          amount
        }
      );

      return res.status(201).json({
        message:
          "Sandbox BTC deposit created. It is pending confirmation.",
        deposit
      });
    } catch (error) {
      console.error(
        "Deposit error:",
        error
      );

      return res.status(500).json({
        error:
          "Could not create deposit"
      });
    }
  }
);

app.post(
  "/deposits/btc/:id/confirm",
  requireAuth,
  async (req, res) => {
    try {
      const deposit =
        await Deposit.findOne({
          _id:
            req.params.id,
          userId:
            req.user._id
        });

      if (!deposit) {
        return res.status(404).json({
          error:
            "Deposit not found"
        });
      }

      if (
        deposit.status ===
        "confirmed"
      ) {
        return res.json({
          message:
            "Deposit already confirmed",
          deposit
        });
      }

      if (
        deposit.status !==
        "pending"
      ) {
        return res.status(400).json({
          error:
            "Deposit cannot be confirmed"
        });
      }

      /*
       * SANDBOX ONLY:
       * This simulates confirmation.
       */

      deposit.status =
        "confirmed";

      deposit.confirmedAt =
        new Date();

      deposit.txid =
        `SANDBOX-TX-${randomToken(
          12
        )}`;

      await deposit.save();

      const account =
        await ensureAccounts(
          req.user._id
        );

      account.availableBalance +=
        deposit.amount;

      await account.save();

      await Ledger.create({
        userId:
          req.user._id,
        type: "deposit",
        currency: "BTC",
        amount:
          deposit.amount,
        description:
          "Sandbox BTC deposit confirmed",
        referenceId:
          String(deposit._id)
      });

      await audit(
        "SANDBOX_BTC_DEPOSIT_CONFIRMED",
        req.user._id,
        {
          depositId:
            String(deposit._id),
          amount:
            deposit.amount
        }
      );

      return res.json({
        message:
          "Sandbox BTC deposit confirmed",
        deposit,
        account
      });
    } catch (error) {
      console.error(
        "Deposit confirmation error:",
        error
      );

      return res.status(500).json({
        error:
          "Could not confirm deposit"
      });
    }
  }
);

app.get(
  "/deposits",
  requireAuth,
  async (req, res) => {
    try {
      const deposits =
        await Deposit.find({
          userId:
            req.user._id
        }).sort({
          createdAt: -1
        });

      return res.json({
        deposits
      });
    } catch (error) {
      console.error(
        "Deposits list error:",
        error
      );

      return res.status(500).json({
        error:
          "Could not load deposits"
      });
    }
  }
);

/* =========================
   SANDBOX BTC WITHDRAWALS
========================= */

app.post(
  "/withdrawals/btc",
  requireAuth,
  async (req, res) => {
    try {
      const amount =
        validBtcAmount(
          req.body.amount
        );

      const address =
        String(
          req.body.address || ""
        ).trim();

      if (amount === null) {
        return res.status(400).json({
          error:
            "Invalid BTC amount"
        });
      }

      if (!address) {
        return res.status(400).json({
          error:
            "BTC address is required"
        });
      }

      const account =
        await ensureAccounts(
          req.user._id
        );

      if (
        account.availableBalance <
        amount
      ) {
        return res.status(400).json({
          error:
            "Insufficient sandbox balance"
        });
      }

      /*
       * SANDBOX ONLY:
       * Reserve the balance and create
       * a withdrawal awaiting admin approval.
       */

      account.availableBalance -=
        amount;

      account.pendingBalance +=
        amount;

      await account.save();

      const withdrawal =
        await Withdrawal.create({
          userId:
            req.user._id,
          currency: "BTC",
          amount,
          address,
          status: "pending"
        });

      await Ledger.create({
        userId:
          req.user._id,
        type: "withdrawal_pending",
        currency: "BTC",
        amount:
          -amount,
        description:
          "Sandbox BTC withdrawal requested",
        referenceId:
          String(withdrawal._id)
      });

      await audit(
        "SANDBOX_BTC_WITHDRAWAL_CREATED",
        req.user._id,
        {
          withdrawalId:
            String(withdrawal._id),
          amount
        }
      );

      return res.status(201).json({
        message:
          "Sandbox withdrawal submitted for approval",
        withdrawal,
        account
      });
    } catch (error) {
      console.error(
        "Withdrawal error:",
        error
      );

      return res.status(500).json({
        error:
          "Could not create withdrawal"
      });
    }
  }
);

app.get(
  "/withdrawals",
  requireAuth,
  async (req, res) => {
    try {
      const withdrawals =
        await Withdrawal.find({
          userId:
            req.user._id
        }).sort({
          createdAt: -1
        });

      return res.json({
        withdrawals
      });
    } catch (error) {
      console.error(
        "Withdrawals list error:",
        error
      );

      return res.status(500).json({
        error:
          "Could not load withdrawals"
      });
    }
  }
);

/* =========================
   TRANSACTIONS
========================= */

app.get(
  "/transactions",
  requireAuth,
  async (req, res) => {
    try {
      const transactions =
        await Ledger.find({
          userId:
            req.user._id
        }).sort({
          createdAt: -1
        });

      return res.json({
        transactions
      });
    } catch (error) {
      console.error(
        "Transactions error:",
        error
      );

      return res.status(500).json({
        error:
          "Could not load transactions"
      });
    }
  }
);

/* =========================
   LOGOUT
========================= */

app.post(
  "/logout",
  requireAuth,
  async (req, res) => {
    try {
      if (req.authToken) {
        await AuthToken.deleteOne({
          _id:
            req.authToken._id
        });
      }

      await audit(
        "USER_LOGOUT",
        req.user._id
      );

      return res.json({
        message:
          "Logged out successfully"
      });
    } catch (error) {
      console.error(
        "Logout error:",
        error
      );

      return res.status(500).json({
        error:
          "Logout failed"
      });
    }
  }
);

/* =========================
   ADMIN
========================= */

app.get(
  "/admin/users",
  requireAdmin,
  async (req, res) => {
    try {
      const users =
        await User.find({})
          .select(
            "_id name email role createdAt"
          )
          .sort({
            createdAt: -1
          });

      return res.json({
        users
      });
    } catch (error) {
      console.error(
        "Admin users error:",
        error
      );

      return res.status(500).json({
        error:
          "Could not load users"
      });
    }
  }
);

app.get(
  "/admin/withdrawals",
  requireAdmin,
  async (req, res) => {
    try {
      const withdrawals =
        await Withdrawal.find({})
          .populate(
            "userId",
            "name email"
          )
          .sort({
            createdAt: -1
          });

      return res.json({
        withdrawals
      });
    } catch (error) {
      console.error(
        "Admin withdrawals error:",
        error
      );

      return res.status(500).json({
        error:
          "Could not load withdrawals"
      });
    }
  }
);

app.post(
  "/admin/withdrawals/:id/approve",
  requireAdmin,
  async (req, res) => {
    try {
      const withdrawal =
        await Withdrawal.findById(
          req.params.id
        );

      if (!withdrawal) {
        return res.status(404).json({
          error:
            "Withdrawal not found"
        });
      }

      if (
        withdrawal.status !==
        "pending"
      ) {
        return res.status(400).json({
          error:
            "Withdrawal is not pending"
        });
      }

      const account =
        await ensureAccounts(
          withdrawal.userId
        );

      account.pendingBalance -=
        withdrawal.amount;

      if (
        account.pendingBalance < 0
      ) {
        account.pendingBalance = 0;
      }

      withdrawal.status =
        "approved";

      withdrawal.reviewedAt =
        new Date();

      /*
       * SANDBOX ONLY:
       * No real blockchain transaction
       * is sent.
       */

      withdrawal.txid =
        `SANDBOX-WITHDRAWAL-${randomToken(
          12
        )}`;

      await withdrawal.save();
      await account.save();

      await Ledger.create({
        userId:
          withdrawal.userId,
        type: "withdrawal_approved",
        currency: "BTC",
        amount:
          -withdrawal.amount,
        description:
          "Sandbox BTC withdrawal approved",
        referenceId:
          String(withdrawal._id)
      });

      await audit(
        "SANDBOX_WITHDRAWAL_APPROVED",
        req.user._id,
        {
          withdrawalId:
            String(
              withdrawal._id
            )
        }
      );

      return res.json({
        message:
          "Sandbox withdrawal approved",
        withdrawal,
        account
      });
    } catch (error) {
      console.error(
        "Admin approve error:",
        error
      );

      return res.status(500).json({
        error:
          "Could not approve withdrawal"
      });
    }
  }
);

app.post(
  "/admin/withdrawals/:id/reject",
  requireAdmin,
  async (req, res) => {
    try {
      const withdrawal =
        await Withdrawal.findById(
          req.params.id
        );

      if (!withdrawal) {
        return res.status(404).json({
          error:
            "Withdrawal not found"
        });
      }

      if (
        withdrawal.status !==
        "pending"
      ) {
        return res.status(400).json({
          error:
            "Withdrawal is not pending"
        });
      }

      const account =
        await ensureAccounts(
          withdrawal.userId
        );

      account.pendingBalance -=
        withdrawal.amount;

      if (
        account.pendingBalance < 0
      ) {
        account.pendingBalance = 0;
      }

      account.availableBalance +=
        withdrawal.amount;

      withdrawal.status =
        "rejected";

      withdrawal.reviewedAt =
        new Date();

      await withdrawal.save();
      await account.save();

      await Ledger.create({
        userId:
          withdrawal.userId,
        type: "withdrawal_rejected",
        currency: "BTC",
        amount:
          withdrawal.amount,
        description:
          "Sandbox BTC withdrawal rejected and balance returned",
        referenceId:
          String(withdrawal._id)
      });

      await audit(
        "SANDBOX_WITHDRAWAL_REJECTED",
        req.user._id,
        {
          withdrawalId:
            String(
              withdrawal._id
            )
        }
      );

      return res.json({
        message:
          "Sandbox withdrawal rejected",
        withdrawal,
        account
      });
    } catch (error) {
      console.error(
        "Admin reject error:",
        error
      );

      return res.status(500).json({
        error:
          "Could not reject withdrawal"
      });
    }
  }
);

/* =========================
   AI CHAT
========================= */

app.post(
  "/ai/chat",
  requireAuth,
  async (req, res) => {
    try {
      if (!OPENAI_API_KEY) {
        return res.status(503).json({
          error:
            "AI service is not configured"
        });
      }

      const message =
        String(
          req.body.message || ""
        ).trim();

      if (!message) {
        return res.status(400).json({
          error:
            "Message is required"
        });
      }

      if (
        message.length > 4000
      ) {
        return res.status(400).json({
          error:
            "Message is too long"
        });
      }

      const client =
        new OpenAI({
          apiKey:
            OPENAI_API_KEY
        });

      const response =
        await client.responses.create(
          {
            model:
              OPENAI_MODEL,

            instructions:
              "You are the CityFive Holdings Ltd sandbox assistant. Clearly distinguish simulated sandbox balances and transactions from real money. Do not claim that sandbox transactions are real blockchain transactions. Do not provide guarantees of investment returns.",

            input: message
          }
        );

      return res.json({
        message:
          response.output_text ||
          "No response generated."
      });
    } catch (error) {
      console.error(
        "AI chat error:",
        error
      );

      return res.status(500).json({
        error:
          "AI request failed"
      });
    }
  }
);

/* =========================
   ERROR HANDLER
========================= */

app.use(
  (
    error,
    req,
    res,
    next
  ) => {
    console.error(
      "Unhandled application error:",
      error
    );

    if (res.headersSent) {
      return next(error);
    }

    return res.status(500).json({
      error:
        "Internal server error"
    });
  }
);

/* =========================
   START SERVER
========================= */

async function start() {
  const server =
    app.listen(
      PORT,
      "0.0.0.0",
      () => {
        console.log(
          `Server listening on port ${PORT}`
        );

        console.log(
          "Platform mode: SANDBOX"
        );

        console.log(
          "Real funds enabled: false"
        );
      }
    );

  const shutdown =
    async (signal) => {
      console.log(
        `${signal} received. Shutting down gracefully...`
      );

      server.close(
        async () => {
          try {
            await mongoose.connection.close();
          } catch (error) {
            console.error(
              "MongoDB shutdown error:",
              error
            );
          }

          process.exit(0);
        }
      );
    };

  process.once(
    "SIGTERM",
    () => shutdown("SIGTERM")
  );

  process.once(
    "SIGINT",
    () => shutdown("SIGINT")
  );

  try {
    await mongoose.connect(
      MONGO_URI
    );

    console.log(
      "DB connected"
    );
  } catch (error) {
    console.error(
      "Database connection failed:",
      error
    );

    server.close(
      () => {
        process.exit(1);
      }
    );
  }
}

start().catch(
  (error) => {
    console.error(
      "Startup failed:",
      error
    );

    process.exit(1);
  }
);
