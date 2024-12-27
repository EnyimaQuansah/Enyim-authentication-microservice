const User = require("../models/User");
const BackblazeB2 = require("backblaze-b2");
const multer = require("multer");
const axios = require('axios');

// Configure multer storage (using memory storage here)
const storage = multer.memoryStorage();
const upload = multer({ storage });


// Initialize Backblaze B2 client
const b2 = new BackblazeB2({
  applicationKeyId: process.env.B2_ACCOUNT_ID,
  applicationKey: process.env.B2_APPLICATION_KEY,
});

// Function to authorize B2 client
const authorizeB2 = async () => {
  try {
    await b2.authorize();
    console.log("Backblaze B2 authorized successfully");
  } catch (error) {
    console.error("Error authorizing Backblaze B2:", error);
  }
};

// Call the authorization function when your application starts
authorizeB2();


exports.editProfile = async (req, res) => {
  try {
    const { name, age, location, shopName, shopDescription, shopAddress } = req.body;
    let profileFileId = null;

    // Find the user to check existing fields
    const user = await User.findById(req.user.user_id);
    if (!user) return res.status(404).json({ error: "User not found." });

    // Handle file upload if a file is provided
    if (req.file) {
      const fileName = `${Date.now()}_${req.file.originalname}`;

      const uploadResponse = await b2.getUploadUrl({ bucketId: process.env.B2_BUCKET_ID });
      if (!uploadResponse.data.uploadUrl || !uploadResponse.data.authorizationToken) {
        throw new Error("Failed to get upload URL from Backblaze B2.");
      }

      const uploadFileResponse = await b2.uploadFile({
        uploadUrl: uploadResponse.data.uploadUrl,
        uploadAuthToken: uploadResponse.data.authorizationToken,
        fileName,
        data: req.file.buffer,
      });

      profileFileId = uploadFileResponse.data.fileName;
      console.log("Profile File ID:", profileFileId);

      if (!profileFileId) {
        return res.status(500).json({ error: "Failed to get file ID from upload response." });
      }
    }

    // Prepare updated data
    const updateData = {
      name: name || user.name,
      age: age || user.age,
      location: location || user.location,
      shopName: shopName || user.shopName,
      shopDescription: shopDescription || user.shopDescription,
      shopAddress: shopAddress || user.shopAddress,
    };

    // Add the profileFileId field if a new file was uploaded or retain the existing value
    if (profileFileId) {
      updateData.profileFileId = profileFileId; // Add or update file ID
    } else if (user.profileFileId) {
      updateData.profileFileId = user.profileFileId; // Retain the existing value
    }

    // Update the user's profile
    const updatedUser = await User.findByIdAndUpdate(req.user.user_id, updateData, { new: true, upsert: true });

    res.json({ message: "Profile updated successfully", user: updatedUser });
  } catch (error) {
    console.error("Error updating profile:", error);
    res.status(500).json({ error: "Failed to update profile." });
  }
};






exports.getProfileById = async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select("-password");
    if (!user) return res.status(404).json({ error: "User not found" });

    let profileImageUrl = null;

    // Generate secure download URL if the user has a profileFileId
    if (user.profileFileId) {
      const authorizeResponse = await axios.get('https://api.backblazeb2.com/b2api/v3/b2_authorize_account', {
        headers: {
          Authorization: `Basic ${Buffer.from(
            `${process.env.B2_APPLICATION_KEY_ID}:${process.env.B2_APPLICATION_KEY}`
          ).toString('base64')}`,
        },
      });

      const {
        apiInfo: { storageApi },
        authorizationToken,
      } = authorizeResponse.data;

      const { downloadUrl } = storageApi;

      if (!downloadUrl || !authorizationToken) {
        throw new Error("Failed to retrieve valid Backblaze B2 configuration.");
      }

      const downloadAuthorizationResponse = await axios.post(
        `${storageApi.apiUrl}/b2api/v3/b2_get_download_authorization`,
        {
          bucketId: process.env.B2_BUCKET_ID,
          fileNamePrefix: user.profileFileId,
          validDurationInSeconds: 3600, // 1-hour validity
        },
        {
          headers: {
            Authorization: authorizationToken,
          },
        }
      );

      profileImageUrl = `${downloadUrl}/file/${process.env.B2_BUCKET_NAME}/${user.profileFileId}?Authorization=${downloadAuthorizationResponse.data.authorizationToken}`;
    }

    res.json({ ...user._doc, profileImageUrl });
  } catch (error) {
    console.error("Error fetching profile:", error.message);
    res.status(500).json({ error: "Internal server error" });
  }
};






exports.getAllProfiles = async (req, res) => {
  try {
    const users = await User.find().select("-password");
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
};
