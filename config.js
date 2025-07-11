import mongoose from "mongoose";

const connect = mongoose.connect("mongodb://localhost:27017/codecollab");

connect
  .then(() => {
    console.log("Database connected");
  })
  .catch(() => {
    console.log("Database not connected");
  });

const loginschema = new mongoose.Schema({
  fullname: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
  },
  password: {
    type: String,
    required: false,
  },
  confirmPassword: {
    type: String,
    required: false,
  },
  googleId: {
    type: String,
    required: false,
    index: true, // Add index for faster lookup
  },
  picture: {
    type: String,
    required: false,
  },
  accessToken: {
    type: String,
    required: false,
  },
  // Add authType to distinguish between local and OAuth users
  authType: {
    type: String,
    enum: ["local", "google"],
    default: "local",
  },
});

// Add compound index for more efficient lookups
loginschema.index({ email: 1, authType: 1 });

const collection = mongoose.model("users", loginschema);

export { collection };
