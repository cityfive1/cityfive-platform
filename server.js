"use strict";

const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");

const {
  btcProviderReady,
  createBtcDepositAddress,
  submitBtcWithdrawal,
  processBtcWebhook,
  verifyWebhook,
  normalizeWebhookEvent
} = require("./fireblocks");

const app = express();

const PORT = Number(process.env.PORT || 3000);

const MONGO_URI = process.env.MONGO_URI || "";

const SESSION_SECRET =
  process.env.SESSION_SECRET || "";

const FRONTEND_ORIGIN =
  process.env.FRONTEND_ORIGIN ||
  "https://cityfive1.github.io";

const PLATFORM_MODE =
  String(process.env.PLATFORM_MODE || "SANDBOX")
    .trim()
    .toUpperCase();

const REAL_FUNDS_ENABLED =
  process.env.REAL_FUNDS_ENABLED === "true";

/*
 * Password reset protection.
 *
 * This secret MUST be configured in Abasthan as:
 *
 * SANDBOX_RESET_KEY
 *
 * Never put it inside GitHub.
 */
const SANDBOX_RESET_KEY =
  process.env.SANDBOX_RESET_KEY || "";

const IS_SANDBOX =
  PLATFORM_MODE === "SANDBOX" &&
  REAL_FUNDS_ENABLED === false;


/* =========================================================
   BASIC VALIDATION
========================================================= */

if (!MONGO_URI) {
  console.error("MONGO_URI is missing.");
  process.exit(1);
}

if (!SESSION_SECRET) {
  console.error("SESSION_SECRET is missing.");
  process.exit(1);
}

if (!FRONTEND_ORIGIN) {
  console.error("FRONTEND_ORIGIN is missing.");
  process.exit(1);
}


/* =========================================================
   CORS
========================================================= */

const allowedOrigins = new Set([
  "https://cityfive1.github.io",
  FRONTEND_ORIGIN,
  "http://localhost:3000",
  "http://127.0.0.1:3000"
]);

const corsOptions = {
  origin(origin, callback) {
    /*
     * Allow requests without an Origin header.
     * Useful for curl/server-to-server health checks.
     */
    if (!origin) {
      return callback(null, true);
    }

    if (allowedOrigins.has(origin)) {
      return callback(null, true);
    }

    return callback(
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
};

app.use(cors(corsOptions));

app.options("*", cors(corsOptions));


/* =========================================================
   FIREBLOCKS WEBHOOK
   Must receive the raw body before express.json()
========================================================= */

app.post(
  "/webhooks/fireblocks",
  express.raw({
    type: "application/json"
  }),
  async (req, res) => {
    try {
      const signature =
        req.headers["fireblocks-webhook-signature"];

      const rawBody = req.body;

      const valid = await verifyWebhook(
        rawBody,
        signature
      );

      if (!valid) {
        return res.status(401).json({
          ok: false,
          error: "Invalid webhook signature"
        });
      }

      let event;

      try {
        event = JSON.parse(
          Buffer.from(rawBody).toString("utf8")
        );
      } catch (error) {
        return res.status(400).json({
          ok: false,
          error: "Invalid webhook JSON"
        });
      }

      const normalized =
        normalizeWebhookEvent(event);

      const result =
        await processBtcWebhook(event);

      console.log(
        "Fireblocks webhook received:",
        normalized
      );

      return res.json({
        ok: true,
        normalized,
        result
      });
    } catch (error) {
      console.error(
        "Fireblocks webhook error:",
        error
      );

      return res.status(500).json({
        ok: false,
        error: "Webhook processing failed"
      });
    }
  }
);


/* =========================================================
   JSON BODY
========================================================= */

app.use(
  express.json({
    limit: "1mb"
  })
);


/* =========================================================
   SESSION
========================================================= */

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
      maxAge: 1000 * 60 * 60 * 24 * 7
    }
  })
);


/* =========================================================
   MONGOOSE SCHEMAS
========================================================= */

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
      enum: [
        "user",
        "admin"
      ],
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

    lastLoginAt: {
      type: Date,
      default: null
    },

    active: {
      type: Boolean,
      default: true
    }
  },
  {
    timestamps: true
  }
);

const User =
  mongoose.model("User", UserSchema);


/* =========================================================
   AUTH TOKEN
========================================================= */

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

const AuthToken =
  mongoose.model(
    "AuthToken",
    AuthTokenSchema
  );


/* =========================================================
   PASSWORD RESET TOKEN
========================================================= */

const PasswordResetSchema = new mongoose.Schema(
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


/* =========================================================
   ACCOUNT
========================================================= */

const AccountSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      index: true
    },

    currency: {
      type: String,
      enum: [
        "CAD",
        "USD",
        "BTC"
      ],
      required: true
    },

    balance: {
      type: Number,
      default: 0
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

const Account =
  mongoose.model(
    "Account",
    AccountSchema
  );


/* =========================================================
   KYC
========================================================= */

const KycProfileSchema = new mongoose.Schema(
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


/* =========================================================
   DEPOSIT
========================================================= */

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
      default: null
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
    }
  },
  {
    timestamps: true
  }
);

const Deposit =
  mongoose.model(
    "Deposit",
    DepositSchema
  );


/* =========================================================
   WITHDRAWAL
========================================================= */

const WithdrawalSchema = new mongoose.Schema(
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


/* =========================================================
   LEDGER
========================================================= */

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
      default: null
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

const Ledger =
  mongoose.model(
    "Ledger",
    LedgerSchema
  );


/* =========================================================
   AUDIT LOG
========================================================= */

const AuditLogSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      default: null,
      index: true
    },

    actorId: {
      type: mongoose.Schema.Types.ObjectId,
      default: null,
      index: true
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

const AuditLog =
  mongoose.model(
    "AuditLog",
    AuditLogSchema
  );


/* =========================================================
   HELPERS
========================================================= */

function normalizeEmail(email) {
  return String(email || "")
    .trim()
    .toLowerCase();
}


function publicUser(user) {
  return {
    id: String(user._id),
    name: user.name,
    email: user.email,
    role: user.role,
    kycStatus: user.kycStatus,
    accountStatus: user.accountStatus,
    active: user.active,
    lastLoginAt: user.lastLoginAt
  };
}


function createRandomToken() {
  return crypto.randomBytes(48).toString("hex");
}


function hashToken(token) {
  return crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");
}


function safeCompareSecret(provided, expected) {
  if (!provided || !expected) {
    return false;
  }

  const a = Buffer.from(String(provided));
  const b = Buffer.from(String(expected));

  if (a.length !== b.length) {
    return false;
  }

  return crypto.timingSafeEqual(a, b);
}


async function issueAuthToken(userId) {
  const token =
    createRandomToken();

  const tokenHash =
    hashToken(token);

  const expiresAt =
    new Date(
      Date.now() +
      1000 * 60 * 60 * 24 * 7
    );

  await AuthToken.create({
    tokenHash,
    userId,
    expiresAt
  });

  return token;
}


async function revokeAuthToken(token) {
  if (!token) {
    return;
  }

  await AuthToken.deleteOne({
    tokenHash: hashToken(token)
  });
}


function getBearerToken(req) {
  const header =
    req.headers.authorization || "";

  if (
    !header.startsWith("Bearer ")
  ) {
    return null;
  }

  return header
    .slice(7)
    .trim();
}


async function getCurrentUser(req) {
  /*
   * Bearer token takes priority.
   */
  const bearer =
    getBearerToken(req);

  if (bearer) {
    const record =
      await AuthToken.findOne({
        tokenHash: hashToken(bearer),
        expiresAt: {
          $gt: new Date()
        }
      });

    if (!record) {
      return null;
    }

    const user =
      await User.findById(
        record.userId
      );

    if (
      !user ||
      !user.active ||
      user.accountStatus === "suspended"
    ) {
      return null;
    }

    return user;
  }

  /*
   * Session fallback.
   */
  if (req.session.userId) {
    const user =
      await User.findById(
        req.session.userId
      );

    if (
      !user ||
      !user.active ||
      user.accountStatus === "suspended"
    ) {
      return null;
    }

    return user;
  }

  return null;
}


async function requireAuth(req, res, next) {
  try {
    const user =
      await getCurrentUser(req);

    if (!user) {
      return res.status(401).json({
        ok: false,
        error: "Authentication required"
      });
    }

    req.user = user;

    next();
  } catch (error) {
    console.error(
      "Authentication error:",
      error
    );

    return res.status(500).json({
      ok: false,
      error: "Authentication failed"
    });
  }
}


async function requireAdmin(req, res, next) {
  try {
    const user =
      await getCurrentUser(req);

    if (
      !user ||
      user.role !== "admin"
    ) {
      return res.status(403).json({
        ok: false,
        error: "Administrator access required"
      });
    }

    req.user = user;

    next();
  } catch (error) {
    console.error(
      "Admin authentication error:",
      error
    );

    return res.status(500).json({
      ok: false,
      error: "Authorization failed"
    });
  }
}


async function audit({
  userId = null,
  actorId = null,
  action,
  details = {},
  ip = ""
}) {
  try {
    await AuditLog.create({
      userId,
      actorId,
      action,
      details,
      ip
    });
  } catch (error) {
    console.error(
      "Audit log error:",
      error
    );
  }
}


function validatePassword(password) {
  /*
   * Minimum 10 characters for this sandbox.
   */
  if (
    typeof password !== "string" ||
    password.length < 10 ||
    password.length > 200
  ) {
    return false;
  }

  return true;
}


/* =========================================================
   HEALTH / ROOT
========================================================= */

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
    ok: true,
    service: "CityFive Holdings Ltd",
    mode: PLATFORM_MODE,
    realFundsEnabled: REAL_FUNDS_ENABLED
  });
});


/* =========================================================
   REGISTER
========================================================= */

app.post(
  "/register",
  async (req, res) => {
    try {
      const name =
        String(req.body.name || "")
          .trim();

      const email =
        normalizeEmail(
          req.body.email
        );

      const password =
        req.body.password;

      if (
        !name ||
        name.length < 2 ||
        name.length > 100
      ) {
        return res.status(400).json({
          ok: false,
          error: "Please enter a valid name."
        });
      }

      if (
        !email ||
        !email.includes("@") ||
        email.length > 200
      ) {
        return res.status(400).json({
          ok: false,
          error: "Please enter a valid email address."
        });
      }

      if (!validatePassword(password)) {
        return res.status(400).json({
          ok: false,
          error:
            "Password must be at least 10 characters."
        });
      }

      const existing =
        await User.findOne({
          email
        });

      if (existing) {
        return res.status(409).json({
          ok: false,
          error: "Email already registered"
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
          passwordHash,
          role: "user",
          kycStatus: "not_started",
          accountStatus: "active",
          active: true
        });

      /*
       * Create initial sandbox accounts.
       */
      await Account.create([
        {
          userId: user._id,
          currency: "CAD",
          balance: 0
        },
        {
          userId: user._id,
          currency: "USD",
          balance: 0
        },
        {
          userId: user._id,
          currency: "BTC",
          balance: 0
        }
      ]);

      await KycProfile.create({
        userId: user._id,
        status: "not_started"
      });

      const token =
        await issueAuthToken(
          user._id
        );

      req.session.userId =
        String(user._id);

      await new Promise(
        (resolve, reject) => {
          req.session.save(
            error => {
              if (error) {
                reject(error);
              } else {
                resolve();
              }
            }
          );
        }
      );

      await audit({
        userId: user._id,
        actorId: user._id,
        action: "REGISTER",
        details: {
          mode: PLATFORM_MODE
        },
        ip: req.ip
      });

      return res.status(201).json({
        ok: true,
        token,
        user: publicUser(user),
        mode: PLATFORM_MODE,
        realFundsEnabled:
          REAL_FUNDS_ENABLED
      });
    } catch (error) {
      console.error(
        "Registration error:",
        error
      );

      if (
        error &&
        error.code === 11000
      ) {
        return res.status(409).json({
          ok: false,
          error: "Email already registered"
        });
      }

      return res.status(500).json({
        ok: false,
        error: "Registration failed"
      });
    }
  }
);


/* =========================================================
   LOGIN
========================================================= */

app.post(
  "/login",
  async (req, res) => {
    try {
      const email =
        normalizeEmail(
          req.body.email
        );

      const password =
        req.body.password;

      if (
        !email ||
        !password
      ) {
        return res.status(401).json({
          ok: false,
          error:
            "Invalid email or password."
        });
      }

      const user =
        await User.findOne({
          email
        });

      if (!user) {
        return res.status(401).json({
          ok: false,
          error:
            "Invalid email or password."
        });
      }

      const passwordMatches =
        await bcrypt.compare(
          password,
          user.passwordHash
        );

      if (!passwordMatches) {
        await audit({
          userId: user._id,
          action: "LOGIN_FAILED",
          details: {
            reason: "invalid_password"
          },
          ip: req.ip
        });

        return res.status(401).json({
          ok: false,
          error:
            "Invalid email or password."
        });
      }

      if (!user.active) {
        return res.status(403).json({
          ok: false,
          error:
            "This account is disabled."
        });
      }

      if (
        user.accountStatus ===
        "suspended"
      ) {
        return res.status(403).json({
          ok: false,
          error:
            "This account is suspended."
        });
      }

      user.lastLoginAt =
        new Date();

      await user.save();

      const token =
        await issueAuthToken(
          user._id
        );

      req.session.userId =
        String(user._id);

      await new Promise(
        (resolve, reject) => {
          req.session.save(
            error => {
              if (error) {
                reject(error);
              } else {
                resolve();
              }
            }
          );
        }
      );

      await audit({
        userId: user._id,
        actorId: user._id,
        action: "LOGIN",
        ip: req.ip
      });

      return res.json({
        ok: true,
        token,
        user: publicUser(user),
        mode: PLATFORM_MODE,
        realFundsEnabled:
          REAL_FUNDS_ENABLED
      });
    } catch (error) {
      console.error(
        "Login error:",
        error
      );

      return res.status(500).json({
        ok: false,
        error: "Login failed"
      });
    }
  }
);


/* =========================================================
   CURRENT USER
========================================================= */

app.get(
  "/me",
  requireAuth,
  async (req, res) => {
    try {
      const accounts =
        await Account.find({
          userId: req.user._id
        }).sort({
          currency: 1
        });

      return res.json({
        ok: true,
        user: publicUser(
          req.user
        ),
        accounts,
        mode: PLATFORM_MODE,
        realFundsEnabled:
          REAL_FUNDS_ENABLED
      });
    } catch (error) {
      console.error(
        "ME error:",
        error
      );

      return res.status(500).json({
        ok: false,
        error: "Unable to load account"
      });
    }
  }
);


/* =========================================================
   SANDBOX PASSWORD RESET
========================================================= */

/*
 * STEP 1
 *
 * POST /sandbox/request-password-reset
 *
 * Body:
 *
 * {
 *   "email": "example@email.com",
 *   "resetKey": "YOUR_SANDBOX_RESET_KEY"
 * }
 *
 * This endpoint is ONLY available in SANDBOX.
 *
 * The reset key is required so somebody cannot simply
 * request a password reset for an account by knowing
 * its email address.
 */

app.post(
  "/sandbox/request-password-reset",
  async (req, res) => {
    try {
      if (!IS_SANDBOX) {
        return res.status(404).json({
          ok: false,
          error: "Not available"
        });
      }

      if (!SANDBOX_RESET_KEY) {
        console.error(
          "SANDBOX_RESET_KEY is not configured."
        );

        return res.status(503).json({
          ok: false,
          error:
            "Sandbox password reset is not configured."
        });
      }

      const resetKey =
        String(
          req.body.resetKey || ""
        );

      if (
        !safeCompareSecret(
          resetKey,
          SANDBOX_RESET_KEY
        )
      ) {
        await audit({
          action:
            "PASSWORD_RESET_REQUEST_REJECTED",
          details: {
            reason: "invalid_reset_key"
          },
          ip: req.ip
        });

        return res.status(403).json({
          ok: false,
          error: "Invalid sandbox reset key."
        });
      }

      const email =
        normalizeEmail(
          req.body.email
        );

      if (!email) {
        return res.status(400).json({
          ok: false,
          error: "Email is required."
        });
      }

      const user =
        await User.findOne({
          email
        });

      /*
       * Do not reveal whether an account exists.
       */
      if (!user) {
        return res.json({
          ok: true,
          message:
            "If the account exists, a reset token has been created."
        });
      }

      /*
       * Remove previous unused reset tokens.
       */
      await PasswordReset.deleteMany({
        userId: user._id,
        usedAt: null
      });

      /*
       * Generate a high-entropy one-time token.
       */
      const resetToken =
        crypto.randomBytes(48)
          .toString("hex");

      const tokenHash =
        hashToken(resetToken);

      const expiresAt =
        new Date(
          Date.now() +
          1000 * 60 * 15
        );

      await PasswordReset.create({
        tokenHash,
        userId: user._id,
        expiresAt
      });

      await audit({
        userId: user._id,
        action:
          "PASSWORD_RESET_REQUESTED",
        details: {
          mode: "SANDBOX",
          expiresInMinutes: 15
        },
        ip: req.ip
      });

      /*
       * In SANDBOX only, the token is returned directly.
       *
       * A production system should deliver this token
       * through a verified email/SMS recovery channel
       * rather than returning it from the API.
       */
      return res.json({
        ok: true,
        message:
          "Sandbox password reset token created.",
        resetToken,
        expiresInSeconds: 900
      });
    } catch (error) {
      console.error(
        "Password reset request error:",
        error
      );

      return res.status(500).json({
        ok: false,
        error:
          "Unable to create password reset request."
      });
    }
  }
);


/*
 * STEP 2
 *
 * POST /sandbox/reset-password
 *
 * Body:
 *
 * {
 *   "resetToken": "...",
 *   "newPassword": "..."
 * }
 */

app.post(
  "/sandbox/reset-password",
  async (req, res) => {
    try {
      if (!IS_SANDBOX) {
        return res.status(404).json({
          ok: false,
          error: "Not available"
        });
      }

      const resetToken =
        String(
          req.body.resetToken || ""
        ).trim();

      const newPassword =
        req.body.newPassword;

      if (
        !resetToken ||
        resetToken.length < 40
      ) {
        return res.status(400).json({
          ok: false,
          error:
            "A valid reset token is required."
        });
      }

      if (
        !validatePassword(
          newPassword
        )
      ) {
        return res.status(400).json({
          ok: false,
          error:
            "Password must be at least 10 characters."
        });
      }

      const tokenHash =
        hashToken(resetToken);

      const resetRecord =
        await PasswordReset.findOne({
          tokenHash,
          usedAt: null,
          expiresAt: {
            $gt: new Date()
          }
        });

      if (!resetRecord) {
        return res.status(400).json({
          ok: false,
          error:
            "Reset token is invalid or expired."
        });
      }

      const user =
        await User.findById(
          resetRecord.userId
        );

      if (!user) {
        return res.status(400).json({
          ok: false,
          error:
            "Reset token is invalid."
        });
      }

      /*
       * Hash the new password.
       */
      const passwordHash =
        await bcrypt.hash(
          newPassword,
          12
        );

      user.passwordHash =
        passwordHash;

      user.active = true;

      if (
        user.accountStatus ===
        "suspended"
      ) {
        user.accountStatus =
          "active";
      }

      await user.save();

      /*
       * Mark the reset token as used.
       */
      resetRecord.usedAt =
        new Date();

      await resetRecord.save();

      /*
       * Revoke all existing bearer tokens
       * for this account.
       */
      await AuthToken.deleteMany({
        userId: user._id
      });

      /*
       * Destroy any current session for this
       * account if it belongs to the same browser.
       */
      if (
        req.session &&
        req.session.userId ===
          String(user._id)
      ) {
        await new Promise(
          resolve => {
            req.session.destroy(
              () => resolve()
            );
          }
        );
      }

      await audit({
        userId: user._id,
        actorId: user._id,
        action:
          "PASSWORD_RESET_COMPLETED",
        details: {
          mode: "SANDBOX"
        },
        ip: req.ip
      });

      return res.json({
        ok: true,
        message:
          "Sandbox password reset completed. Please sign in with the new password."
      });
    } catch (error) {
      console.error(
        "Password reset error:",
        error
      );

      return res.status(500).json({
        ok: false,
        error:
          "Unable to reset password."
      });
    }
  }
);


/* =========================================================
   START KYC
========================================================= */

app.post(
  "/kyc/start",
  requireAuth,
  async (req, res) => {
    try {
      const kyc =
        await KycProfile.findOneAndUpdate(
          {
            userId: req.user._id
          },
          {
            status: "pending",
            submittedAt: new Date()
          },
          {
            new: true,
            upsert: true
          }
        );

      req.user.kycStatus =
        "pending";

      await req.user.save();

      await audit({
        userId: req.user._id,
        actorId: req.user._id,
        action: "KYC_STARTED",
        ip: req.ip
      });

      return res.json({
        ok: true,
        kyc
      });
    } catch (error) {
      console.error(
        "KYC error:",
        error
      );

      return res.status(500).json({
        ok: false,
        error:
          "Unable to start KYC."
      });
    }
  }
);


/* =========================================================
   SANDBOX BTC DEPOSIT
========================================================= */

app.post(
  "/deposits/btc",
  requireAuth,
  async (req, res) => {
    try {
      /*
       * Real funds are disabled.
       */
      if (
        !IS_SANDBOX
      ) {
        if (!btcProviderReady()) {
          return res.status(503).json({
            ok: false,
            error:
              "BTC provider is not enabled."
          });
        }
      }

      /*
       * Sandbox deposit.
       */
      if (IS_SANDBOX) {
        const deposit =
          await Deposit.create({
            userId:
              req.user._id,
            asset: "BTC",
            amount: 0,
            address: null,
            txid: null,
            status: "pending",
            mode: "SANDBOX"
          });

        await audit({
          userId: req.user._id,
          actorId: req.user._id,
          action:
            "SANDBOX_BTC_DEPOSIT_CREATED",
          details: {
            depositId:
              String(deposit._id)
          },
          ip: req.ip
        });

        return res.json({
          ok: true,
          mode: "SANDBOX",
          realFundsEnabled: false,
          deposit
        });
      }

      /*
       * Real provider adapter is intentionally not
       * enabled in this build.
       */
      const result =
        await createBtcDepositAddress({
          userId:
            String(req.user._id)
        });

      return res.json({
        ok: true,
        result
      });
    } catch (error) {
      console.error(
        "BTC deposit error:",
        error
      );

      return res.status(500).json({
        ok: false,
        error:
          "Unable to create BTC deposit."
      });
    }
  }
);


/* =========================================================
   SANDBOX BTC WITHDRAWAL
========================================================= */

app.post(
  "/withdrawals/btc",
  requireAuth,
  async (req, res) => {
    try {
      const amount =
        Number(req.body.amount);

      const address =
        String(
          req.body.address || ""
        ).trim();

      if (
        !Number.isFinite(amount) ||
        amount <= 0
      ) {
        return res.status(400).json({
          ok: false,
          error:
            "Enter a valid BTC amount."
        });
      }

      if (
        !address ||
        address.length > 200
      ) {
        return res.status(400).json({
          ok: false,
          error:
            "Enter a valid BTC address."
        });
      }

      /*
       * Sandbox withdrawal.
       */
      if (IS_SANDBOX) {
        const withdrawal =
          await Withdrawal.create({
            userId:
              req.user._id,
            asset: "BTC",
            amount,
            address,
            status: "pending",
            mode: "SANDBOX"
          });

        await audit({
          userId: req.user._id,
          actorId: req.user._id,
          action:
            "SANDBOX_BTC_WITHDRAWAL_CREATED",
          details: {
            withdrawalId:
              String(
                withdrawal._id
              ),
            amount
          },
          ip: req.ip
        });

        return res.json({
          ok: true,
          mode: "SANDBOX",
          realFundsEnabled: false,
          withdrawal
        });
      }

      const result =
        await submitBtcWithdrawal({
          userId:
            String(req.user._id),
          amount,
          address,
          reference:
            crypto.randomUUID()
        });

      return res.json({
        ok: true,
        result
      });
    } catch (error) {
      console.error(
        "BTC withdrawal error:",
        error
      );

      return res.status(500).json({
        ok: false,
        error:
          "Unable to create BTC withdrawal."
      });
    }
  }
);


/* =========================================================
   ACCOUNTS
========================================================= */

app.get(
  "/accounts",
  requireAuth,
  async (req, res) => {
    try {
      const accounts =
        await Account.find({
          userId:
            req.user._id
        }).sort({
          currency: 1
        });

      return res.json({
        ok: true,
        accounts
      });
    } catch (error) {
      console.error(
        "Accounts error:",
        error
      );

      return res.status(500).json({
        ok: false,
        error:
          "Unable to load accounts."
      });
    }
  }
);


/* =========================================================
   TRANSACTIONS
========================================================= */

app.get(
  "/transactions",
  requireAuth,
  async (req, res) => {
    try {
      const [
        deposits,
        withdrawals,
        ledger
      ] =
        await Promise.all([
          Deposit.find({
            userId:
              req.user._id
          })
            .sort({
              createdAt: -1
            })
            .limit(100),

          Withdrawal.find({
            userId:
              req.user._id
          })
            .sort({
              createdAt: -1
            })
            .limit(100),

          Ledger.find({
            userId:
              req.user._id
          })
            .sort({
              createdAt: -1
            })
            .limit(100)
        ]);

      const transactions = [
        ...deposits.map(item => ({
          id: String(item._id),
          type: "deposit",
          asset: item.asset,
          amount: item.amount,
          status: item.status,
          createdAt: item.createdAt,
          mode: item.mode
        })),

        ...withdrawals.map(item => ({
          id: String(item._id),
          type: "withdrawal",
          asset: item.asset,
          amount: item.amount,
          status: item.status,
          createdAt: item.createdAt,
          mode: item.mode
        })),

        ...ledger.map(item => ({
          id: String(item._id),
          type: item.type,
          asset: item.currency,
          amount: item.amount,
          status: "posted",
          description:
            item.description,
          createdAt: item.createdAt,
          mode: PLATFORM_MODE
        }))
      ];

      transactions.sort(
        (a, b) =>
          new Date(b.createdAt) -
          new Date(a.createdAt)
      );

      return res.json({
        ok: true,
        transactions
      });
    } catch (error) {
      console.error(
        "Transactions error:",
        error
      );

      return res.status(500).json({
        ok: false,
        error:
          "Unable to load transactions."
      });
    }
  }
);


/* =========================================================
   LOGOUT
========================================================= */

app.post(
  "/logout",
  async (req, res) => {
    try {
      const bearer =
        getBearerToken(req);

      if (bearer) {
        await revokeAuthToken(
          bearer
        );
      }

      if (req.session) {
        await new Promise(
          resolve => {
            req.session.destroy(
              () => resolve()
            );
          }
        );
      }

      return res.json({
        ok: true
      });
    } catch (error) {
      console.error(
        "Logout error:",
        error
      );

      return res.json({
        ok: true
      });
    }
  }
);


/* =========================================================
   ADMIN STATUS
========================================================= */

app.get(
  "/admin/status",
  requireAdmin,
  async (req, res) => {
    const [
      users,
      pendingKyc,
      pendingWithdrawals
    ] =
      await Promise.all([
        User.countDocuments(),

        KycProfile.countDocuments({
          status: "pending"
        }),

        Withdrawal.countDocuments({
          status: "pending"
        })
      ]);

    return res.json({
      ok: true,
      mode: PLATFORM_MODE,
      realFundsEnabled:
        REAL_FUNDS_ENABLED,
      users,
      pendingKyc,
      pendingWithdrawals
    });
  }
);


/* =========================================================
   ADMIN USERS
========================================================= */

app.get(
  "/admin/users",
  requireAdmin,
  async (req, res) => {
    try {
      const users =
        await User.find()
          .select(
            "_id name email role kycStatus accountStatus active createdAt lastLoginAt"
          )
          .sort({
            createdAt: -1
          })
          .limit(500);

      return res.json({
        ok: true,
        users
      });
    } catch (error) {
      console.error(
        "Admin users error:",
        error
      );

      return res.status(500).json({
        ok: false,
        error:
          "Unable to load users."
      });
    }
  }
);


/* =========================================================
   ADMIN KYC LIST
========================================================= */

app.get(
  "/admin/kyc",
  requireAdmin,
  async (req, res) => {
    try {
      const records =
        await KycProfile.find()
          .sort({
            createdAt: -1
          })
          .limit(500)
          .lean();

      return res.json({
        ok: true,
        records
      });
    } catch (error) {
      console.error(
        "Admin KYC error:",
        error
      );

      return res.status(500).json({
        ok: false,
        error:
          "Unable to load KYC records."
      });
    }
  }
);


/* =========================================================
   ADMIN APPROVE KYC
========================================================= */

app.post(
  "/admin/kyc/:id/approve",
  requireAdmin,
  async (req, res) => {
    try {
      const kyc =
        await KycProfile.findById(
          req.params.id
        );

      if (!kyc) {
        return res.status(404).json({
          ok: false,
          error:
            "KYC record not found."
        });
      }

      kyc.status =
        "approved";

      kyc.reviewedAt =
        new Date();

      kyc.reviewNote =
        "Approved by administrator.";

      await kyc.save();

      await User.findByIdAndUpdate(
        kyc.userId,
        {
          kycStatus:
            "approved"
        }
      );

      await audit({
        userId:
          kyc.userId,
        actorId:
          req.user._id,
        action:
          "KYC_APPROVED",
        ip: req.ip
      });

      return res.json({
        ok: true,
        kyc
      });
    } catch (error) {
      console.error(
        "Approve KYC error:",
        error
      );

      return res.status(500).json({
        ok: false,
        error:
          "Unable to approve KYC."
      });
    }
  }
);


/* =========================================================
   ADMIN REJECT KYC
========================================================= */

app.post(
  "/admin/kyc/:id/reject",
  requireAdmin,
  async (req, res) => {
    try {
      const kyc =
        await KycProfile.findById(
          req.params.id
        );

      if (!kyc) {
        return res.status(404).json({
          ok: false,
          error:
            "KYC record not found."
        });
      }

      const note =
        String(
          req.body.note || ""
        ).trim();

      kyc.status =
        "rejected";

      kyc.reviewedAt =
        new Date();

      kyc.reviewNote =
        note ||
        "Rejected by administrator.";

      await kyc.save();

      await User.findByIdAndUpdate(
        kyc.userId,
        {
          kycStatus:
            "rejected"
        }
      );

      await audit({
        userId:
          kyc.userId,
        actorId:
          req.user._id,
        action:
          "KYC_REJECTED",
        details: {
          note
        },
        ip: req.ip
      });

      return res.json({
        ok: true,
        kyc
      });
    } catch (error) {
      console.error(
        "Reject KYC error:",
        error
      );

      return res.status(500).json({
        ok: false,
        error:
          "Unable to reject KYC."
      });
    }
  }
);


/* =========================================================
   ADMIN WITHDRAWALS
========================================================= */

app.get(
  "/admin/withdrawals",
  requireAdmin,
  async (req, res) => {
    try {
      const withdrawals =
        await Withdrawal.find()
          .sort({
            createdAt: -1
          })
          .limit(500);

      return res.json({
        ok: true,
        withdrawals
      });
    } catch (error) {
      console.error(
        "Admin withdrawals error:",
        error
      );

      return res.status(500).json({
        ok: false,
        error:
          "Unable to load withdrawals."
      });
    }
  }
);


/* =========================================================
   ADMIN APPROVE WITHDRAWAL
========================================================= */

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
          ok: false,
          error:
            "Withdrawal not found."
        });
      }

      if (
        withdrawal.status !==
        "pending"
      ) {
        return res.status(400).json({
          ok: false,
          error:
            "Withdrawal is not pending."
        });
      }

      /*
       * In SANDBOX, approval changes only the
       * simulated status.
       */
      if (IS_SANDBOX) {
        withdrawal.status =
          "approved";

        await withdrawal.save();

        await audit({
          userId:
            withdrawal.userId,
          actorId:
            req.user._id,
          action:
            "SANDBOX_WITHDRAWAL_APPROVED",
          details: {
            withdrawalId:
              String(
                withdrawal._id
              )
          },
          ip: req.ip
        });

        return res.json({
          ok: true,
          mode: "SANDBOX",
          withdrawal
        });
      }

      return res.status(503).json({
        ok: false,
        error:
          "Live withdrawal processing is not enabled."
      });
    } catch (error) {
      console.error(
        "Approve withdrawal error:",
        error
      );

      return res.status(500).json({
        ok: false,
        error:
          "Unable to approve withdrawal."
      });
    }
  }
);


/* =========================================================
   ADMIN REJECT WITHDRAWAL
========================================================= */

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
          ok: false,
          error:
            "Withdrawal not found."
        });
      }

      if (
        withdrawal.status !==
        "pending"
      ) {
        return res.status(400).json({
          ok: false,
          error:
            "Withdrawal is not pending."
        });
      }

      const reason =
        String(
          req.body.reason || ""
        ).trim();

      withdrawal.status =
        "rejected";

      withdrawal.rejectionReason =
        reason ||
        "Rejected by administrator.";

      await withdrawal.save();

      await audit({
        userId:
          withdrawal.userId,
        actorId:
          req.user._id,
        action:
          "WITHDRAWAL_REJECTED",
        details: {
          withdrawalId:
            String(
              withdrawal._id
            ),
          reason
        },
        ip: req.ip
      });

      return res.json({
        ok: true,
        withdrawal
      });
    } catch (error) {
      console.error(
        "Reject withdrawal error:",
        error
      );

      return res.status(500).json({
        ok: false,
        error:
          "Unable to reject withdrawal."
      });
    }
  }
);


/* =========================================================
   ADMIN AUDIT LOG
========================================================= */

app.get(
  "/admin/audit",
  requireAdmin,
  async (req, res) => {
    try {
      const logs =
        await AuditLog.find()
          .sort({
            createdAt: -1
          })
          .limit(500);

      return res.json({
        ok: true,
        logs
      });
    } catch (error) {
      console.error(
        "Audit error:",
        error
      );

      return res.status(500).json({
        ok: false,
        error:
          "Unable to load audit logs."
      });
    }
  }
);


/* =========================================================
   404 HANDLER
========================================================= */

app.use(
  (req, res) => {
    res.status(404).json({
      ok: false,
      error: "Endpoint not found"
    });
  }
);


/* =========================================================
   ERROR HANDLER
========================================================= */

app.use(
  (error, req, res, next) => {
    console.error(
      "Unhandled server error:",
      error
    );

    if (
      res.headersSent
    ) {
      return next(error);
    }

    return res.status(500).json({
      ok: false,
      error:
        "Internal server error"
    });
  }
);


/* =========================================================
   DATABASE + SERVER
========================================================= */

async function startServer() {
  try {
    console.log(
      "Connecting to MongoDB..."
    );

    await mongoose.connect(
      MONGO_URI
    );

    console.log(
      "DB connected"
    );

    console.log(
      `Platform mode: ${PLATFORM_MODE}`
    );

    console.log(
      `Real funds enabled: ${REAL_FUNDS_ENABLED}`
    );

    console.log(
      `Sandbox password reset: ${
        IS_SANDBOX &&
        Boolean(SANDBOX_RESET_KEY)
          ? "enabled"
          : "disabled"
      }`
    );

    app.listen(
      PORT,
      "0.0.0.0",
      () => {
        console.log(
          `Server listening on port ${PORT}`
        );
      }
    );
  } catch (error) {
    console.error(
      "Startup failed:",
      error
    );

    process.exit(1);
  }
}


startServer();
