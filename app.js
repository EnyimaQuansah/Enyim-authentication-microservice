require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");

const authRoutes = require("./routes/authRoutes");
const profileRoutes = require("./routes/profileRoutes");
const { connectDB } = require("./utils/db");

const app = express();


// Middleware
app.use(cors({origin: ["http://localhost:4444", "http://localhost:8000"], credentials: true}));

app.use(bodyParser.json({ limit: "5mb" }));

// Database Connection
connectDB();

// Routes
app.use("/auth", authRoutes);
app.use("/auth/profile", profileRoutes);

module.exports = app;