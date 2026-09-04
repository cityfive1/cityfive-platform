const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const crypto = require("crypto");

const {
  verifyWebhook,
  normalizeWebhookEvent
} = require("./fireblocks");

const app = express();
