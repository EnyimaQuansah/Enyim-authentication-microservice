const User = require("../models/User");
const bcrypt = require("bcrypt");
const rabbitMQ = require("../utils/rabbitmq");
const {
  generateAccessToken,
  generateRefreshToken,
  storeRefreshToken,
  verifyToken,
  getStoredRefreshToken,
  revokeRefreshToken,
} = require("../utils/tokenManager");

// Register new user
exports.register = async (req, res) => {
  try {
    const { username, email, password, role } = req.body;

    const allowedRoles = ["USER", "SHOP_OWNER", "ADMIN"];
    if (role && !allowedRoles.includes(role)) {
      return res.status(400).json({ message: "Invalid role specified" });
    }

    const userExists = await User.findOne({ $or: [{ username }, { email }] });
    if (userExists) {
      return res.status(400).json({ message: "Username or email already exists" });
    }

    const user = new User({
      username,
      email,
      password,
      role: role || "USER",
    });

    await user.save();

     // Send the first RabbitMQ message
     try {
      await rabbitMQ.sendMessage("user_data_sync", { id: user._id, username, email, role: user.role });
    } catch (mqError) {
      console.error("RabbitMQ Error (user_data_sync):", mqError.message);
    }
    // Use setTimeout to send the second message after a delay
    setTimeout(async () => {
      try {
        await rabbitMQ.sendMessage("auth_events", {
          type: "user_created",
          data: { userId: user._id, username, email, role: user.role },
        });
      } catch (error) {
        console.error("RabbitMQ Error (auth_events):", error.message);
      }
    }, 3000);


    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    console.error("Register Error:", error.message);
    res.status(500).json({ error: "Internal server error" });
  }
};

// Login user
exports.login = async (req, res) => {
  try {
    const { username, password } = req.body;

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const payload = { id: user._id, role: user.role };

    const accessToken = generateAccessToken(payload);

    const refreshToken = generateRefreshToken(payload);

    await storeRefreshToken(user._id.toString(), refreshToken);

    // Emit user login event
    try {
      await rabbitMQ.sendMessage("auth_events", {
        type: "user_logged_in",
        data: { userId: user._id, username },
      });
    } catch (error) {
      console.error("RabbitMQ Error:", error.message);
    }

    res.json({
      accessToken,
      refreshToken,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    console.error("Login Error:", error.message);
    res.status(500).json({ error: "Internal server error" });
  }
};

// Refresh token
exports.refreshToken = async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({ error: "Refresh token is required" });
    }

    const decoded = verifyToken(refreshToken, process.env.JWT_REFRESH_SECRET);

    const storedToken = await getStoredRefreshToken(decoded.user_id);
    if (storedToken !== refreshToken) {
      return res.status(403).json({ error: "Invalid or expired refresh token" });
    }

    const payload = { id: decoded.user_id, role: decoded.role };

    const newAccessToken = generateAccessToken(payload);
    const newRefreshToken = generateRefreshToken(payload);

    await storeRefreshToken(decoded.user_id, newRefreshToken);

    res.json({ accessToken: newAccessToken, refreshToken: newRefreshToken });
  } catch (error) {
    console.error("Refresh Token Error:", error.message);
    res.status(403).json({ error: "Invalid or expired refresh token" });
  }
};

// Logout user
exports.logout = async (req, res) => {
  try {
    const { userId } = req.body;

    if (!userId) {
      return res.status(400).json({ error: "User ID is required" });
    }

    await revokeRefreshToken(userId);

    try {
      await rabbitMQ.sendMessage("auth_events", {
        type: "user_logged_out",
        data: { userId },
      });
    } catch (error) {
      console.error("RabbitMQ Error:", error.message);
    }

    res.json({ message: "Logged out successfully" });
  } catch (error) {
    console.error("Logout Error:", error.message);
    res.status(500).json({ error: "Internal server error" });
  }
};
