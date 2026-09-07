"use strict";

const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const OpenAI = require("openai");

const app = express();

const PORT = Number(process.env.PORT || 3000);
const MONGO_URI = process.env.MONGO_URI || "";
const FRONTEND_ORIGIN =
  process.env.FRONTEND_ORIGIN || "https://cityfive1.github.io";
const SESSION_SECRET = process.env.SESSION_SECRET || "";
const PLATFORM_MODE = String(
  process.env.PLATFORM_MODE || "SANDBOX"
).toUpperCase();
const REAL_FUNDS_ENABLED =
  process.env.REAL_FUNDS_ENABLED === "true";
const IS_SANDBOX =
  PLATFORM_MODE === "SANDBOX" && !REAL_FUNDS_ENABLED;
const SANDBOX_RESET_KEY =
  process.env.SANDBOX_RESET_KEY || "";
const OPENAI_API_KEY =
  process.env.OPENAI_API_KEY || "";
const OPENAI_MODEL =
  process.env.OPENAI_MODEL || "gpt-5.5";

if (!MONGO_URI || !SESSION_SECRET) {
  console.error(
    "MONGO_URI and SESSION_SECRET are required."
  );
  process.exit(1);
}

if (!IS_SANDBOX) {
  console.error(
    "Phase 1 build is sandbox-only. Set PLATFORM_MODE=SANDBOX and REAL_FUNDS_ENABLED=false."
  );
  process.exit(1);
}

const allowedOrigins = new Set([
  FRONTEND_ORIGIN,
  "https://cityfive1.github.io",
  "http://localhost:3000",
  "http://127.0.0.1:3000"
]);

app.set("trust proxy", 1);

app.use(
  cors({
    origin(origin, cb) {
      if (!origin || allowedOrigins.has(origin)) {
        return cb(null, true);
      }

      return cb(
        new Error("CORS origin not allowed")
      );
    },
    credentials: true,
    methods: [
      "GET",
      "POST",
      "PUT",
      "PATCH",
      "DELETE",
      "OPTIONS"
    ],
    allowedHeaders: [
      "Content-Type",
      "Authorization"
    ]
  })
);

app.use(
  express.json({
    limit: "1mb"
  })
);

/* ---------- models ---------- */

const UserSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
      maxlength: 100
    },

    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true
    },

    passwordHash: {
      type: String,
      required: true
    },

    role: {
      type: String,
      enum: ["user", "admin"],
      default: "user"
    },

    kycStatus: {
      type: String,
      enum: [
        "not_started",
        "pending",
        "approved",
        "rejected"
      ],
      default: "not_started"
    },

    accountStatus: {
      type: String,
      enum: [
        "pending",
        "active",
        "suspended"
      ],
      default: "active"
    },

    active: {
      type: Boolean,
      default: true
    },

    lastLoginAt: {
      type: Date,
      default: null
    }
  },
  {
    timestamps: true
  }
);

const User = mongoose.model(
  "User",
  UserSchema
);

const AuthTokenSchema = new mongoose.Schema(
  {
    tokenHash: {
      type: String,
      required: true,
      unique: true,
      index: true
    },

    userId: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      index: true
    },

    expiresAt: {
      type: Date,
      required: true,
      index: true
    }
  },
  {
    timestamps: true
  }
);

const AuthToken = mongoose.model(
  "AuthToken",
  AuthTokenSchema
);

const PasswordResetSchema =
  new mongoose.Schema(
    {
      tokenHash: {
        type: String,
        required: true,
        unique: true,
        index: true
      },

      userId: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        index: true
      },

      expiresAt: {
        type: Date,
        required: true,
        index: true
      },

      usedAt: {
        type: Date,
        default: null
      }
    },
    {
      timestamps: true
    }
  );

const PasswordReset =
  mongoose.model(
    "PasswordReset",
    PasswordResetSchema
  );

const AccountSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      index: true
    },

    currency: {
      type: String,
      enum: ["CAD", "USD", "BTC"],
      required: true
    },

    balance: {
      type: Number,
      default: 0,
      min: 0
    }
  },
  {
    timestamps: true
  }
);

AccountSchema.index(
  {
    userId: 1,
    currency: 1
  },
  {
    unique: true
  }
);

const Account = mongoose.model(
  "Account",
  AccountSchema
);

const DepositSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      index: true
    },

    asset: {
      type: String,
      default: "BTC"
    },

    amount: {
      type: Number,
      required: true
    },

    address: {
      type: String,
      default: null
    },

    txid: {
      type: String,
      default: null,
      index: true
    },

    status: {
      type: String,
      enum: [
        "pending",
        "confirmed",
        "rejected"
      ],
      default: "pending"
    },

    mode: {
      type: String,
      default: "SANDBOX"
    },

    confirmations: {
      type: Number,
      default: 0
    },

    requiredConfirmations: {
      type: Number,
      default: 3
    },

    creditApplied: {
      type: Boolean,
      default: false
    }
  },
  {
    timestamps: true
  }
);

const Deposit = mongoose.model(
  "Deposit",
  DepositSchema
);

const WithdrawalSchema =
  new mongoose.Schema(
    {
      userId: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        index: true
      },

      asset: {
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

      txid: {
        type: String,
        default: null
      },

      status: {
        type: String,
        enum: [
          "pending",
          "approved",
          "rejected",
          "submitted",
          "completed"
        ],
        default: "pending"
      },

      mode: {
        type: String,
        default: "SANDBOX"
      },

      rejectionReason: {
        type: String,
        default: ""
      }
    },
    {
      timestamps: true
    }
  );

const Withdrawal =
  mongoose.model(
    "Withdrawal",
    WithdrawalSchema
  );

const LedgerSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      index: true
    },

    currency: {
      type: String,
      required: true
    },

    type: {
      type: String,
      enum: [
        "deposit",
        "withdrawal",
        "adjustment"
      ],
      required: true
    },

    amount: {
      type: Number,
      required: true
    },

    referenceId: {
      type: String,
      required: true
    },

    description: {
      type: String,
      default: ""
    }
  },
  {
    timestamps: true
  }
);

LedgerSchema.index(
  {
    type: 1,
    referenceId: 1
  },
  {
    unique: true
  }
);

const Ledger = mongoose.model(
  "Ledger",
  LedgerSchema
);

const KycProfileSchema =
  new mongoose.Schema(
    {
      userId: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        unique: true,
        index: true
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

      submittedAt: {
        type: Date,
        default: null
      },

      reviewedAt: {
        type: Date,
        default: null
      },

      reviewNote: {
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
    KycProfileSchema
  );

const AuditSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      default: null,
      index: true
    },

    actorId: {
      type: mongoose.Schema.Types.ObjectId,
      default: null
    },

    action: {
      type: String,
      required: true
    },

    details: {
      type: mongoose.Schema.Types.Mixed,
      default: {}
    },

    ip: {
      type: String,
      default: ""
    }
  },
  {
    timestamps: true
  }
);

const Audit = mongoose.model(
  "Audit",
  AuditSchema
);

/* ---------- helpers ---------- */

const sha256 = (value) =>
  crypto
    .createHash("sha256")
    .update(String(value))
    .digest("hex");

const publicUser = (u) => ({
  id: String(u._id),
  name: u.name,
  email: u.email,
  role: u.role,
  kycStatus: u.kycStatus,
  accountStatus: u.accountStatus,
  active: u.active
});

async function audit(data) {
  try {
    await Audit.create(data);
  } catch (e) {
    console.error(
      "audit error:",
      e.message
    );
  }
}

async function issueToken(userId) {
  const raw =
    crypto
      .randomBytes(48)
      .toString("hex");

  await AuthToken.create({
    tokenHash: sha256(raw),
    userId,
    expiresAt: new Date(
      Date.now() +
        7 * 24 * 60 * 60 * 1000
    )
  });

  return raw;
}

function bearer(req) {
  const value =
    req.headers.authorization || "";

  return value.startsWith("Bearer ")
    ? value.slice(7).trim()
    : "";
}

async function requireAuth(
  req,
  res,
  next
) {
  try {
    const raw = bearer(req);

    if (!raw) {
      return res.status(401).json({
        ok: false,
        error:
          "Authentication required."
      });
    }

    const token =
      await AuthToken.findOne({
        tokenHash: sha256(raw),
        expiresAt: {
          $gt: new Date()
        }
      });

    if (!token) {
      return res.status(401).json({
        ok: false,
        error:
          "Invalid or expired session."
      });
    }

    const user =
      await User.findById(
        token.userId
      );

    if (
      !user ||
      !user.active ||
      user.accountStatus ===
        "suspended"
    ) {
      return res.status(403).json({
        ok: false,
        error:
          "Account unavailable."
      });
    }

    req.user = user;
    req.authToken = token;

    next();
  } catch (e) {
    next(e);
  }
}

async function requireAdmin(
  req,
  res,
  next
) {
  if (
    req.user.role !== "admin"
  ) {
    return res.status(403).json({
      ok: false,
      error:
        "Admin access required."
    });
  }

  next();
}

async function ensureAccounts(
  userId
) {
  for (
    const currency of [
      "CAD",
      "USD",
      "BTC"
    ]
  ) {
    await Account.updateOne(
      {
        userId,
        currency
      },
      {
        $setOnInsert: {
          userId,
          currency,
          balance: 0
        }
      },
      {
        upsert: true
      }
    );
  }
}

function validBtcAmount(
  value
) {
  const n = Number(value);

  return (
    Number.isFinite(n) &&
    n > 0 &&
    n <= 100
  );
}

/* ---------- public ---------- */

app.get("/", (req, res) => {
  res.json({
    service:
      "CityFive Holdings Ltd",
    status: "online",
    mode: "SANDBOX",
    realFundsEnabled: false,
    phase: 1,
    message:
      "Sandbox build. No real BTC is moved."
  });
});

app.get(
  "/health",
  (req, res) =>
    res.json({
      ok: true,
      mode: "SANDBOX",
      realFundsEnabled: false
    })
);

/* ---------- authentication ---------- */

app.post(
  "/register",
  async (req, res, next) => {
    try {
      const name =
        String(
          req.body.name || ""
        ).trim();

      const email =
        String(
          req.body.email || ""
        )
          .trim()
          .toLowerCase();

      const password =
        String(
          req.body.password || ""
        );

      if (
        !name ||
        !email ||
        password.length < 10
      ) {
        return res
          .status(400)
          .json({
            ok: false,
            error:
              "Name, valid email and a password of at least 10 characters are required."
          });
      }

      if (
        await User.findOne({
          email
        })
      ) {
        return res
          .status(409)
          .json({
            ok: false,
            error:
              "Email already registered."
          });
      }

      const passwordHash =
        await bcrypt.hash(
          password,
          12
        );

      const user =
        await User.create({
          name,
          email,
          passwordHash
        });

      await ensureAccounts(
        user._id
      );

      await audit({
        userId: user._id,
        actorId: user._id,
        action:
          "USER_REGISTERED",
        ip: req.ip
      });

      const token =
        await issueToken(
          user._id
        );

      res.status(201).json({
        ok: true,
        token,
        user: publicUser(user),
        mode: "SANDBOX",
        realFundsEnabled: false
      });
    } catch (e) {
      next(e);
    }
  }
);

app.post(
  "/login",
  async (req, res, next) => {
    try {
      const email =
        String(
          req.body.email || ""
        )
          .trim()
          .toLowerCase();

      const password =
        String(
          req.body.password || ""
        );

      const user =
        await User.findOne({
          email
        });

      if (
        !user ||
        !(await bcrypt.compare(
          password,
          user.passwordHash
        ))
      ) {
        return res
          .status(401)
          .json({
            ok: false,
            error:
              "Invalid email or password."
          });
      }

      if (
        !user.active ||
        user.accountStatus ===
          "suspended"
      ) {
        return res
          .status(403)
          .json({
            ok: false,
            error:
              "Account unavailable."
          });
      }

      user.lastLoginAt =
        new Date();

      await user.save();

      await ensureAccounts(
        user._id
      );

      const token =
        await issueToken(
          user._id
        );

      res.json({
        ok: true,
        token,
        user: publicUser(user),
        mode: "SANDBOX",
        realFundsEnabled: false
      });
    } catch (e) {
      next(e);
    }
  }
);

app.get(
  "/me",
  requireAuth,
  async (req, res, next) => {
    try {
      const accounts =
        await Account.find({
          userId: req.user._id
        }).sort({
          currency: 1
        });

      res.json({
        ok: true,
        user: publicUser(
          req.user
        ),
        accounts,
        mode: "SANDBOX",
        realFundsEnabled: false
      });
    } catch (e) {
      next(e);
    }
  }
);
