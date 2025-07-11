import express from "express";
import { collection } from "./config.js";
import bodyParser from "body-parser";
import path from "path";
import { fileURLToPath } from "url";
import * as fs from "fs";
import dotenv from "dotenv";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as GoogleStrategy } from "passport-google-oauth2";
import session from "express-session";
import randomInteger from "random-int";
import { v4 as uuidv4 } from "uuid";
import { createServer } from "http";
import { Server } from "socket.io";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Initialize express app
const app = express();
const port = process.env.PORT || 3002;
const httpServer = createServer(app);

// Add health check endpoint for Vercel
app.get("/api/health", (req, res) => {
  res.status(200).json({ status: "ok", timestamp: new Date().toISOString() });
});

// Add request logging middleware for debugging
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// Add error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send("Something broke!");
});
const io = new Server(httpServer, {
  cors: {
    origin: process.env.NODE_ENV === "production" ? [/\.vercel\.app$/] : "*",
    methods: ["GET", "POST"],
    credentials: true,
  },
  transports: ["websocket", "polling"],
  allowEIO3: true,
  path: "/socket.io/",
});

// Store active rooms and users
const activeRooms = new Map();

// Configure session
// Session middleware with Vercel-compatible settings
app.use(
  session({
    secret:
      process.env.SESSION_SECRET ||
      "codecollab_dev_secret_replace_in_production",
    resave: false,
    saveUninitialized: true,
    cookie: {
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
    },
    // Memory store is fine for Vercel serverless functions
    // For production, consider using a database or Redis store
  }),
);

// Initialize passport
app.use(passport.initialize());
app.use(passport.session());

// Configure passport serialization
passport.serializeUser((user, done) => {
  // For Google OAuth users, use googleId as the session identifier
  // For local users, use MongoDB _id
  const userId =
    user.googleId || (user._id ? user._id.toString() : null) || user.id;
  console.log("Serializing user:", userId);
  done(null, userId);
});

passport.deserializeUser(async (id, done) => {
  try {
    console.log("Deserializing user ID:", id);

    // Try to find by googleId first (for Google OAuth users)
    let user = await collection.findOne({ googleId: id });

    if (!user) {
      // If not found by googleId, try other ID formats
      try {
        // Only attempt ObjectId conversion if it might be a valid ObjectId
        if (/^[0-9a-fA-F]{24}$/.test(id)) {
          user = await collection.findOne({ _id: id });
        }
      } catch (objIdError) {
        console.log("Not a valid ObjectId, continuing with string search");
      }

      // If still not found, try by string id
      if (!user) {
        user = await collection.findOne({ id: id });
      }
    }

    // Log the found user
    if (user) {
      console.log("User found by ID:", id);
      console.log("User auth type:", user.authType || "not set");
    }

    if (!user) {
      console.log("User not found during deserialization");
      return done(null, false);
    }

    console.log("User found during deserialization:", user.email);
    return done(null, user);
  } catch (err) {
    console.error("Error during deserialization:", err);
    return done(err, null);
  }
});

// Configure Local Strategy for email/password login
passport.use(
  new LocalStrategy(
    {
      usernameField: "email",
      passwordField: "password",
    },
    async (email, password, done) => {
      try {
        // Look for local auth users
        const user = await collection.findOne({
          email: email,
          $or: [{ authType: "local" }, { authType: { $exists: false } }],
        });
        if (!user) {
          return done(null, false, { message: "User not found" });
        }
        if (user.password !== password) {
          return done(null, false, { message: "Incorrect password" });
        }
        return done(null, user);
      } catch (err) {
        return done(err);
      }
    },
  ),
);

// Configure Google Strategy
passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_GOOGLE_SECRET,
      callbackURL: "http://localhost:3002/auth/google/callback",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        console.log("Google profile:", profile);
        console.log("Looking up Google user with ID:", profile.id);
        let user = await collection.findOne({ googleId: profile.id });

        // Create user object with necessary profile data
        const userData = {
          googleId: profile.id,
          fullname: profile.displayName,
          picture: profile.photos?.[0]?.value,
          email: profile.emails?.[0]?.value,
          accessToken: accessToken,
          authType: "google", // Set auth type to google
        };

        if (!user) {
          // Insert new user
          console.log("Creating new user from Google profile");
          const result = await collection.insertOne(userData);
          console.log("User created:", result);
          console.log("Returning userData with googleId:", userData.googleId);
          return cb(null, userData);
        } else {
          // Update existing user
          console.log("Updating existing user from Google profile");
          const result = await collection.updateOne(
            { googleId: profile.id },
            { $set: userData },
          );
          console.log("User updated:", result);
          // Return the updated user data with the googleId as identifier, not the old data
          console.log(
            "Returning updated userData with googleId:",
            userData.googleId,
          );
          return cb(null, userData);
        }
      } catch (error) {
        console.error("Error processing Google authentication:", error);
        return cb(error, null);
      }
    },
  ),
);

// Middleware to make user available to all templates
app.use((req, res, next) => {
  // For debugging
  console.log("Session ID:", req.session.id);
  console.log("User in session:", req.user);

  // Make user data available to templates
  res.locals.user = req.user || null;
  next();
});

// Set up EJS as view engine
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// Serve static files
app.use(
  "/css",
  express.static(path.join(__dirname, "public/css"), { maxAge: 0 }),
);
app.use(
  "/img",
  express.static(path.join(__dirname, "public/img"), { maxAge: 0 }),
);
app.use(express.static(path.join(__dirname, "public"), { maxAge: 0 }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json()); // For JSON requests

// Routes
app.get("/", (req, res) => {
  // Check if user is in session
  if (req.user) {
    res.redirect("/dashboard");
  } else {
    res.render("home.ejs", { title: "Home" });
  }
});

app.get("/dashboard", (req, res) => {
  console.log("Dashboard route accessed, user in session:", req.user);
  console.log("Session ID:", req.session.id);
  console.log("Auth type:", req.session.authType || "not set");

  // Check if user is in session
  if (req.user) {
    res.render("dashboard.ejs", {
      title: "Dashboard",
    });
  } else {
    res.redirect("/auth/signin");
  }
});

// Room join route
app.get("/room/join", (req, res) => {
  // Check if user is in session
  if (!req.user) {
    return res.redirect("/auth/signin");
  }

  const roomId = req.query.id;
  const roomPassword = req.query.password;

  if (!roomId) {
    return res.redirect("/dashboard");
  }

  // In a real implementation, you would fetch the room from a database
  // For now, we'll check if the room exists in our active rooms
  const roomExists = activeRooms.has(roomId);

  // If room doesn't exist yet but is stored in session (created by this user)
  const isCreator = roomId.toString() === req.session.lastCreatedRoomId;

  // Check if room requires password
  if (isCreator) {
    // Room creator doesn't need to enter password
    console.log(
      `Room creator ${req.user.fullname || "Anonymous"} is joining room ${roomId}`,
    );
  } else if (roomExists) {
    // For a real app, you would check against a stored password in a database
    // For this demo, we'll simplify and assume if a password was provided, it's correct
    const requiresPassword = req.session.isPasswordProtected;

    if (requiresPassword && !roomPassword) {
      // Redirect back to dashboard with error
      return res.redirect(
        `/dashboard?error=Password required for room ${roomId}`,
      );
    }

    console.log(
      `User ${req.user.fullname || "Anonymous"} is joining room ${roomId}`,
    );
  }

  // Redirect to the room
  res.redirect(`/room/${roomId}`);
});

// Room creation route
app.post("/room/create", (req, res) => {
  // Check if user is in session
  if (!req.user) {
    return res.redirect("/auth/signin");
  }

  // Get room details from form
  const {
    roomName,
    roomLanguage,
    roomDescription,
    roomVisibility,
    roomPassword,
    isPasswordProtected,
  } = req.body;

  // Generate a random room ID (6-digit number)
  const roomId = randomInteger(100000, 999999);

  // In a real implementation, you would save the room to the database
  // For now, we'll just log the information and redirect to the room
  console.log("Creating room:", {
    id: roomId,
    name: roomName,
    language: roomLanguage,
    description: roomDescription,
    visibility: roomVisibility,
    hasPassword: isPasswordProtected === "on",
    password: isPasswordProtected === "on" ? roomPassword : null,
    createdBy: req.user._id || req.user.id || req.user.googleId,
    createdAt: new Date(),
  });

  // Store room information in session for later use
  req.session.roomName = roomName;
  req.session.roomLanguage = roomLanguage;
  req.session.roomDescription = roomDescription;
  req.session.roomVisibility = roomVisibility;

  // Store password if room is password protected
  if (isPasswordProtected === "on" && roomPassword) {
    req.session.roomPassword = roomPassword;
    req.session.isPasswordProtected = true;
  } else {
    req.session.roomPassword = null;
    req.session.isPasswordProtected = false;
  }

  // Store the room ID of the last created room
  req.session.lastCreatedRoomId = roomId;

  // Store password if room is password protected
  if (isPasswordProtected === "on" && roomPassword) {
    req.session.roomPassword = roomPassword;
    req.session.isPasswordProtected = true;
  } else {
    req.session.roomPassword = null;
    req.session.isPasswordProtected = false;
  }

  // Store the room ID of the last created room
  req.session.lastCreatedRoomId = roomId;

  // Redirect to the room page
  res.redirect(`/room/${roomId}`);
});

app.get("/room/:roomId", (req, res) => {
  console.log("Room route accessed, user in session:", req.user);
  // Check if user is in session
  if (req.user) {
    // In a real implementation, you would fetch room data from the database
    const roomId = req.params.roomId;

    // For now, we'll create mock data based on the roomId
    const roomData = {
      name: req.session.roomName || "Coding Room " + roomId,
      language: req.session.roomLanguage || "JavaScript",
      id: roomId,
      description: req.session.roomDescription || "A collaborative coding room",
      visibility: req.session.roomVisibility || "public",
      isPasswordProtected: req.session.isPasswordProtected || false,
      createdAt: new Date(),
      createdBy: req.user._id || req.user.id || req.user.googleId,
      files: [
        { name: "index.js", type: "js", content: "// JavaScript code here" },
        {
          name: "index.html",
          type: "html",
          content: "<!-- HTML code here -->",
        },
        { name: "styles.css", type: "css", content: "/* CSS code here */" },
      ],
    };

    // Clear session variables after use
    delete req.session.roomName;
    delete req.session.roomLanguage;
    delete req.session.roomDescription;
    delete req.session.roomVisibility;

    res.render("room.ejs", {
      title: roomData.name + " | CodeCollab",
      roomData,
    });
  } else {
    res.redirect("/auth/signin");
  }
});

app.get("/auth/signin", (req, res) => {
  res.render("signin.ejs", { title: "Sign In" });
});

app.get("/auth/signup", (req, res) => {
  res.render("signup.ejs", { title: "Sign Up" });
});

app.get("/auth/forgot-password", (req, res) => {
  res.render("forgot-password.ejs", { title: "Forgot Password" });
});

// Google OAuth routes
app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  }),
);

app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/auth/signin" }),
  function (req, res) {
    console.log("Google auth successful, redirecting to dashboard");
    console.log("User authenticated:", req.user);
    console.log("Session after Google auth:", req.session);
    // Store auth type in session for debugging
    req.session.authType = "google";
    res.redirect("/dashboard");
  },
);

// Auth routes
app.post("/auth/signup", async (req, res) => {
  const data = {
    fullname: req.body.fullname,
    email: req.body.email,
    password: req.body.password,
    confirmPassword: req.body.confirmPassword,
    authType: "local", // Set auth type to local
  };

  const namecheck = await collection.findOne({ fullname: data.fullname });
  const emailcheck = await collection.findOne({ email: data.email });

  if (namecheck && emailcheck) {
    res.send("Email and Full name already exists");
  } else if (namecheck) {
    res.send("Full name already exists");
  } else if (emailcheck) {
    res.send("Email already exists");
  } else {
    if (data.password === data.confirmPassword) {
      collection.insertMany([data]);
      res.render("signin.ejs", { title: "Sign In" });
    } else {
      res.send("Both password and confirm password are not same");
    }
  }
});

// Login route with Passport
app.post(
  "/auth/signin",
  passport.authenticate("local", {
    successRedirect: "/dashboard",
    failureRedirect: "/auth/signin",
    failureFlash: false,
  }),
);

// Manual login route for debugging
app.post("/auth/local-login", async (req, res) => {
  try {
    // Look for local users by email and authType
    const user = await collection.findOne({
      email: req.body.email,
      $or: [{ authType: "local" }, { authType: { $exists: false } }],
    });

    if (!user) {
      return res.render("signin.ejs", {
        title: "Sign In",
        error: "User not found",
      });
    }

    if (user.password !== req.body.password) {
      return res.render("signin.ejs", {
        title: "Sign In",
        error: "Incorrect password",
      });
    }

    req.login(user, (err) => {
      if (err) {
        console.error("Manual login error:", err);
        return res.render("signin.ejs", {
          title: "Sign In",
          error: "Login error: " + err.message,
        });
      }

      console.log("Manual login successful");
      return res.redirect("/dashboard");
    });
  } catch (error) {
    console.error("Manual login error:", error);
    res.render("signin.ejs", {
      title: "Sign In",
      error: "Error: " + error.message,
    });
  }
});

// Logout route
app.get("/auth/signout", (req, res, next) => {
  // Clear the session
  req.session.destroy((err) => {
    if (err) {
      console.error("Error destroying session:", err);
      return next(err);
    }
    res.redirect("/");
  });
});

// Room status API endpoint
app.get("/api/rooms/status", (req, res) => {
  // Check if user is authenticated
  if (!req.user) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const roomsStatus = [];

  // Format the rooms data for the response
  for (const [roomId, users] of activeRooms.entries()) {
    // Check if this is the room created by the current user
    const isCreatedByCurrentUser =
      roomId.toString() === req.session.lastCreatedRoomId;

    roomsStatus.push({
      roomId,
      userCount: users.size,
      isPasswordProtected: isCreatedByCurrentUser
        ? req.session.isPasswordProtected
        : false,
      users: Array.from(users.values()).map((user) => ({
        userId: user.userId,
        username: user.username,
        picture: user.picture,
      })),
    });
  }

  res.json({
    activeRooms: roomsStatus,
    totalRooms: activeRooms.size,
    totalUsers: [...activeRooms.values()].reduce(
      (total, users) => total + users.size,
      0,
    ),
  });
});

// Socket.IO setup
io.on("connection", (socket) => {
  console.log("A user connected:", socket.id);

  // Handle joining a room
  socket.on("join_room", (roomData) => {
    const { roomId, userId, username, picture, password } = roomData;

    // Check if room is password protected and validate password
    // This would be more robust in a real implementation

    // Join the Socket.IO room
    socket.join(roomId);

    // Add user to the active room
    if (!activeRooms.has(roomId)) {
      activeRooms.set(roomId, new Map());
    }

    const roomUsers = activeRooms.get(roomId);
    roomUsers.set(socket.id, {
      userId,
      username,
      picture,
      socketId: socket.id,
      joinedAt: new Date(),
    });

    // Notify all users in the room that a new user joined
    io.to(roomId).emit("user_joined", {
      userId,
      username,
      picture,
      socketId: socket.id,
      userCount: roomUsers.size,
    });

    // Send the current list of users to the new user
    const usersList = Array.from(roomUsers.values());
    socket.emit("room_users", usersList);

    console.log(`User ${username} (${socket.id}) joined room ${roomId}`);
  });

  // Handle code changes
  socket.on("code_change", (data) => {
    const { roomId, code, language, userId, cursorPosition } = data;

    // Broadcast the code change to all other users in the room
    socket.to(roomId).emit("code_updated", {
      code,
      language,
      userId,
      cursorPosition,
    });
  });

  // Handle cursor position updates
  socket.on("cursor_move", (data) => {
    const { roomId, userId, username, cursorPosition } = data;

    // Broadcast the cursor position to all other users in the room
    socket.to(roomId).emit("cursor_updated", {
      userId,
      username,
      cursorPosition,
    });
  });

  // Handle chat messages
  socket.on("send_message", (data) => {
    const { roomId, userId, username, picture, message, timestamp } = data;

    // Broadcast the message to all users in the room
    io.to(roomId).emit("new_message", {
      userId,
      username,
      picture,
      message,
      timestamp,
    });
  });

  // Handle disconnection
  socket.on("disconnect", () => {
    console.log("User disconnected:", socket.id);

    // Find which room the user was in
    for (const [roomId, users] of activeRooms.entries()) {
      if (users.has(socket.id)) {
        const userData = users.get(socket.id);

        // Remove the user from the room
        users.delete(socket.id);

        // If the room is empty, remove it
        if (users.size === 0) {
          activeRooms.delete(roomId);
        } else {
          // Notify others that the user left
          io.to(roomId).emit("user_left", {
            userId: userData.userId,
            username: userData.username,
            userCount: users.size,
          });
        }

        console.log(`User ${userData.username} left room ${roomId}`);
        break;
      }
    }
  });
});

// Error handling for Vercel serverless environment
const handleServerError = (err) => {
  console.error("Server error:", err);
  // In production, you might want to log to a service
  if (process.env.NODE_ENV === "production") {
    // Log to your preferred service
    console.error("Production server error:", err.message, err.stack);
  }
};

// Start the server
httpServer
  .listen(port, () => {
    console.log("Server is listening on port:", port);
  })
  .on("error", handleServerError);

// For serverless environments like Vercel, also export the app
// This allows Vercel to import the Express app directly
export default app;

// Log a warning if no session secret is set
if (!process.env.SESSION_SECRET) {
  console.warn(
    "WARNING: No SESSION_SECRET environment variable set. Using a fallback secret.",
  );
  console.warn(
    "For production, set a strong SESSION_SECRET in your environment variables.",
  );
}
// Log static file paths for debugging in Vercel
console.log("Static files path:", path.join(__dirname, "public"));
console.log("CSS files path:", path.join(__dirname, "public/css"));
console.log(
  "CSS file exists:",
  fs.existsSync(path.join(__dirname, "public/css/ios-style.css")),
);

// Handle unhandled promise rejections
process.on("unhandledRejection", (reason, promise) => {
  console.error("Unhandled Rejection at:", promise, "reason:", reason);
  // In a production environment, you may want to do additional logging
});
