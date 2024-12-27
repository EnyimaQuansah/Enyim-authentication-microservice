const express = require("express");
const multer = require("multer");
const { editProfile, getProfileById, getAllProfiles } = require("../controllers/profileController");
const { authenticateToken, validateRole } = require("../middleware/authMiddleware");

const router = express.Router();
const upload = multer(); // Middleware for file upload

// Profile CRUD operations
router.put("/edit", authenticateToken, validateRole(['USER', 'SHOP_OWNER','ADMIN']), upload.single("profileImage"), editProfile);
router.get("/:id",  authenticateToken, validateRole(['USER', 'SHOP_OWNER','ADMIN']), getProfileById);
router.get("/",  authenticateToken, validateRole(['USER', 'SHOP_OWNER','ADMIN']), getAllProfiles);

module.exports = router;
