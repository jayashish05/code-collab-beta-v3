import express from "express";
import { collection, Room, safeDBOperation, ensureDBConnection, connectDB } from "./config.js";
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
import crypto from "crypto"; // Add crypto import for session ID generation

// Validate required environment variables for Vercel
const requiredEnvVars = ['MONGODB_URI'];
const missingEnvVars = requiredEnvVars.filter(varName => !process.env[varName]);

if (missingEnvVars.length > 0) {
  console.error('Missing required environment variables:', missingEnvVars);
  console.error('Please set these variables in your Vercel dashboard or .env file');
  // Don't exit in serverless environment, just log the error
  if (process.env.NODE_ENV !== 'production') {
    process.exit(1);
  }
}

// Log environment status for debugging
console.log('Environment variables status:');
console.log('NODE_ENV:', process.env.NODE_ENV);
console.log('VERCEL_ENV:', process.env.VERCEL_ENV);
console.log('MONGODB_URI:', process.env.MONGODB_URI ? 'Set' : 'Not set');
console.log('SESSION_SECRET:', process.env.SESSION_SECRET ? 'Set' : 'Using default');
console.log('CLIENT_ID:', process.env.CLIENT_ID ? 'Set' : 'Not set');
console.log('CLIENT_GOOGLE_SECRET:', process.env.CLIENT_GOOGLE_SECRET ? 'Set' : 'Not set');

dotenv.config();

// Initialize database connection
console.log('Initializing database connection...');
connectDB()
  .then(() => {
    console.log('Database connection initialized successfully');
  })
  .catch((error) => {
    console.error('Failed to initialize database connection:', error);
    console.error('The application will continue but database operations may fail');
  });

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Initialize express app
const app = express();
const port = process.env.PORT || 3002;
const httpServer = createServer(app);

// Add health check endpoint
app.get("/api/health", (req, res) => {
  res.status(200).json({
    status: "ok",
    timestamp: new Date().toISOString(),
    env: process.env.NODE_ENV || "development",
    dirname: __dirname,
    staticPaths: {
      public: path.join(__dirname, "public"),
      css: path.join(__dirname, "public/css"),
      js: path.join(__dirname, "public/js"),
      img: path.join(__dirname, "public/img"),
    },
  });
});

// Add request logging middleware for debugging
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// Socket.IO setup with improved configuration
const io = new Server(httpServer, {
  cors: {
    origin: "*", // Allow all origins for development
    methods: ["GET", "POST"],
    credentials: true,
  },
  transports: ["websocket", "polling"],
  allowEIO3: true,
  path: "/socket.io/",
  pingInterval: 10000, // Check connection every 10 seconds
  pingTimeout: 5000, // Consider connection closed if no response after 5 seconds
  cookie: false, // Disable socket.io cookie for better performance
  maxHttpBufferSize: 1e8, // Increase buffer size for larger code payloads
});

// Store active rooms and users
const activeRooms = new Map();
// Map to store user information by room
const roomUsers = new Map();
// Store cursor colors for users
const userColors = new Map();
// Store bash execution queue to prevent overload
const bashQueue = [];
// Flag to indicate if we're currently processing a bash command
let processingBash = false;

// Configure session with proper settings for both localhost and Vercel
const isProduction = process.env.NODE_ENV === "production";
const isVercel = process.env.VERCEL_ENV !== undefined;

// Enhanced session configuration for different hosting environments
const sessionConfig = {
  secret: process.env.SESSION_SECRET || "codecollab_dev_secret_replace_in_production_12345",
  resave: false,
  saveUninitialized: false,
  rolling: true, // Reset expiration on activity
  cookie: {
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    httpOnly: true,
    secure: false, // Will be set dynamically based on environment
    sameSite: "lax", // Use lax for better compatibility
    domain: undefined, // Let browser handle domain automatically
    path: "/", // Ensure cookies work for all paths
  },
  name: "codecollab.sid",
  // Add session debugging
  genid: function(req) {
    const sessionId = crypto.randomBytes(16).toString('hex');
    console.log("Generating new session ID:", sessionId);
    return sessionId;
  }
};

// Adjust session security settings based on environment
if (isProduction || isVercel || process.env.HTTPS === 'true') {
  // Use secure cookies for production/HTTPS environments
  sessionConfig.cookie.secure = false; // Keep false for Vercel proxy compatibility
  console.log("Session configured for production/HTTPS environment");
} else {
  // Development environment
  sessionConfig.cookie.secure = false;
  console.log("Session configured for development environment");
}

app.use(session(sessionConfig));

// Initialize passport
app.use(passport.initialize());
app.use(passport.session());

// Configure passport serialization
passport.serializeUser((user, done) => {
  // For all users, use email as the session identifier for consistency
  // Fall back to googleId if email isn't available (shouldn't happen but just in case)
  const userId =
    user.email || user.googleId || (user._id ? user._id.toString() : null);
  if (!userId) {
    console.error("Failed to serialize user - no identifier found:", user);
    return done(new Error("No valid user identifier found"), null);
  }
  console.log("Serializing user:", userId);
  done(null, userId);
});

passport.deserializeUser(async (id, done) => {
  try {
    console.log("Deserializing user ID:", id);

    // Use safe database operation with retry logic
    let user = null;
    
    // Check if the ID looks like an email
    if (id.includes("@")) {
      // Try to find by email first
      user = await safeDBOperation(async () => {
        return await collection.findOne({ email: id });
      });
      
      if (user) {
        console.log("User found by email:", user.email);
        return done(null, user);
      }
    }

    // If not found by email or not an email, try other identifiers
    // Try to find by googleId
    if (!user) {
      user = await safeDBOperation(async () => {
        return await collection.findOne({ googleId: id });
      });
      
      if (user) {
        console.log("User found by googleId:", user.email);
        return done(null, user);
      }
    }

    // Try to find by _id as last resort
    if (!user) {
      try {
        if (/^[0-9a-fA-F]{24}$/.test(id)) {
          user = await safeDBOperation(async () => {
            return await collection.findOne({ _id: id });
          });
          
          if (user) {
            console.log("User found by _id:", user.email);
            return done(null, user);
          }
        }
      } catch (err) {
        console.log("Error looking up by _id:", err.message);
      }
    }

    console.log("User not found during deserialization for ID:", id);
    return done(null, false);
  } catch (err) {
    console.error("Error during deserialization:", err);
    console.error("Deserialization error stack:", err.stack);
    
    // In serverless environments, database connections might be intermittent
    // Return false instead of error to prevent authentication loops
    if (err.message.includes('timeout') || err.message.includes('buffering') || 
        err.name === 'MongoNetworkError' || err.name === 'MongoTimeoutError') {
      console.error("Database connection/timeout issue during deserialization, returning false");
      return done(null, false);
    }
    
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
        console.log(`Attempting to authenticate user with email: ${email}`);

        // Use safe database operation with retry logic
        const user = await safeDBOperation(async () => {
          return await collection.findOne({
            email: email,
            $or: [{ authType: "local" }, { authType: { $exists: false } }],
          });
        });

        if (!user) {
          console.log(`User with email ${email} not found`);
          return done(null, false, { message: "User not found" });
        }

        if (user.password !== password) {
          console.log(`Incorrect password for user with email ${email}`);
          return done(null, false, { message: "Incorrect password" });
        }

        console.log(`User ${email} authenticated successfully:`, user.email);
        return done(null, user);
      } catch (err) {
        console.error(`Authentication error: ${err.message}`);
        console.error(`Authentication error stack: ${err.stack}`);
        
        // Handle specific database errors in serverless environments
        if (err.message.includes('timeout') || err.message.includes('buffering') || 
            err.name === 'MongoNetworkError' || err.name === 'MongoTimeoutError') {
          console.error("Database connection/timeout issue during authentication");
          return done(null, false, { message: "Database connection temporarily unavailable. Please try again." });
        }
        
        return done(err);
      }
    },
  ),
);

/**
 * Dynamic URL Detection and Environment Configuration
 * 
 * This section handles automatic detection of the application's base URL
 * for different hosting environments:
 * 
 * 1. Vercel Production: https://code-collab-beta-v3.vercel.app
 * 2. Vercel Preview: https://[deployment-url].vercel.app  
 * 3. GitHub Codespaces: https://[codespace-name]-[port].app.github.dev
 * 4. Port Forwarding: Uses FORWARDED_URL environment variable
 * 5. Localhost with custom port: http://localhost:[PORT]
 * 6. Localhost default: http://localhost:3002
 * 
 * The URL detection supports:
 * - Request-based detection (using headers like x-forwarded-host, x-forwarded-proto)
 * - Environment variable overrides (BASE_URL, GOOGLE_CALLBACK_URL)
 * - Automatic protocol detection (HTTP/HTTPS)
 * - Proxy and load balancer compatibility
 */

// Enhanced environment detection and URL configuration
const isVercelEnvironment = process.env.VERCEL_ENV || process.env.VERCEL_URL;
const isVercelProduction = process.env.VERCEL_ENV === 'production';
const isCodespaces = process.env.CODESPACE_NAME || process.env.GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN;
const isCustomPort = process.env.PORT && process.env.PORT !== '3002';

// Function to get the current base URL dynamically
function getBaseURL(req = null) {
  // Priority 1: Explicitly set base URL
  if (process.env.BASE_URL) {
    return process.env.BASE_URL;
  }
  
  // Priority 2: Request-based detection (when available)
  if (req) {
    // Check for forwarded headers (common in reverse proxies)
    const forwardedProto = req.headers['x-forwarded-proto'] || 
                          req.headers['x-forwarded-protocol'] ||
                          req.headers['cloudfront-forwarded-proto'];
    
    const forwardedHost = req.headers['x-forwarded-host'] || 
                         req.headers['x-forwarded-server'] ||
                         req.headers['x-original-host'];
    
    // Determine protocol
    let protocol = forwardedProto || (req.connection.encrypted ? 'https' : 'http');
    if (protocol.includes(',')) {
      protocol = protocol.split(',')[0].trim(); // Take first protocol if multiple
    }
    
    // Determine host
    const host = forwardedHost || 
                req.headers.host || 
                req.get('host') ||
                req.hostname;
    
    if (host) {
      // Clean up the host (remove port if it's standard)
      let cleanHost = host;
      if ((protocol === 'https' && host.endsWith(':443')) ||
          (protocol === 'http' && host.endsWith(':80'))) {
        cleanHost = host.split(':')[0];
      }
      
      return `${protocol}://${cleanHost}`;
    }
  }
  
  // Priority 3: Environment-based detection
  if (isVercelEnvironment) {
    if (isVercelProduction) {
      return "https://code-collab-beta-v3.vercel.app";
    } else if (process.env.VERCEL_URL) {
      return `https://${process.env.VERCEL_URL}`;
    }
  }
  
  // Priority 4: Codespaces detection
  if (isCodespaces) {
    const codespaceName = process.env.CODESPACE_NAME;
    const port = process.env.PORT || '3002';
    if (codespaceName) {
      return `https://${codespaceName}-${port}.app.github.dev`;
    }
    
    // Alternative codespace format
    if (process.env.GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN) {
      return `https://${port}-${process.env.GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN}`;
    }
  }
  
  // Priority 5: Custom port forwarding
  if (process.env.FORWARDED_URL) {
    return process.env.FORWARDED_URL;
  }
  
  // Priority 6: Localhost with custom port
  if (isCustomPort) {
    const protocol = process.env.HTTPS === 'true' ? 'https' : 'http';
    return `${protocol}://localhost:${process.env.PORT}`;
  }
  
  // Priority 7: Default localhost
  const protocol = process.env.HTTPS === 'true' ? 'https' : 'http';
  return `${protocol}://localhost:3002`;
}

// Determine the appropriate callback URL and base URL based on environment
let googleCallbackURL;
let baseURL;

if (process.env.GOOGLE_CALLBACK_URL) {
  // Use explicitly set callback URL (highest priority)
  googleCallbackURL = process.env.GOOGLE_CALLBACK_URL;
  // Extract base URL from callback URL
  baseURL = googleCallbackURL.replace('/auth/google/callback', '');
} else {
  // Get base URL and construct callback URL
  baseURL = getBaseURL();
  googleCallbackURL = `${baseURL}/auth/google/callback`;
}

console.log("Enhanced Environment Detection:");
console.log("- VERCEL_ENV:", process.env.VERCEL_ENV);
console.log("- VERCEL_URL:", process.env.VERCEL_URL);
console.log("- NODE_ENV:", process.env.NODE_ENV);
console.log("- CODESPACE_NAME:", process.env.CODESPACE_NAME);
console.log("- GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN:", process.env.GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN);
console.log("- PORT:", process.env.PORT);
console.log("- HTTPS:", process.env.HTTPS);
console.log("- BASE_URL:", process.env.BASE_URL);
console.log("- FORWARDED_URL:", process.env.FORWARDED_URL);
console.log("- GOOGLE_CALLBACK_URL:", process.env.GOOGLE_CALLBACK_URL);
console.log("Environment flags:");
console.log("- isVercelEnvironment:", isVercelEnvironment);
console.log("- isVercelProduction:", isVercelProduction);
console.log("- isCodespaces:", isCodespaces);
console.log("- isCustomPort:", isCustomPort);
console.log("Computed URLs:");
console.log("- Base URL:", baseURL);
console.log("- Google OAuth Callback URL:", googleCallbackURL);

passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID || process.env.GOOGLE_CLIENT_ID,
      clientSecret:
        process.env.CLIENT_GOOGLE_SECRET || process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: googleCallbackURL,
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
      passReqToCallback: true,
      proxy: true, // Important for working with proxied connections
    },
    async (req, accessToken, refreshToken, profile, cb) => {
      try {
        console.log("Google profile:", profile.id, profile.displayName);
        console.log("Looking up Google user with ID:", profile.id);

        if (!profile.id || !profile.emails || !profile.emails[0].value) {
          console.error("Invalid Google profile data");
          return cb(new Error("Invalid Google profile data"), null);
        }

        // Use safe database operation to find user by Google ID
        let user = await safeDBOperation(async () => {
          return await collection.findOne({ googleId: profile.id });
        });

        // Create user object with necessary profile data
        const userData = {
          googleId: profile.id,
          fullname: profile.displayName,
          picture: profile.photos?.[0]?.value,
          email: profile.emails[0].value,
          accessToken: accessToken,
          authType: "google", // Set auth type to google
          lastLogin: new Date(),
        };

        if (!user) {
          // Insert new user
          console.log("Creating new user from Google profile");
          try {
            // Use safe database operation for user creation
            const result = await safeDBOperation(async () => {
              return await collection.insertOne(userData);
            });
            
            console.log("User created:", result.insertedId);
            // Make sure we have the _id field for consistency
            userData._id = result.insertedId;
            console.log("Returning userData with googleId:", userData.googleId);
            return cb(null, userData);
          } catch (insertError) {
            console.error("Error creating user:", insertError);
            // Check if this was a duplicate key error (maybe email already exists)
            if (insertError.code === 11000) {
              // Try to find by email using safe operation
              const existingUser = await safeDBOperation(async () => {
                return await collection.findOne({
                  email: userData.email,
                });
              });
              
              if (existingUser) {
                // Update this user with Google info using safe operation
                const updateResult = await safeDBOperation(async () => {
                  return await collection.updateOne(
                    { email: userData.email },
                    {
                      $set: {
                        googleId: userData.googleId,
                        picture: userData.picture,
                        accessToken: userData.accessToken,
                        lastLogin: new Date(),
                      },
                    },
                  );
                });
                
                console.log(
                  "Linked existing account with Google:",
                  updateResult.modifiedCount,
                );
                return cb(null, { ...existingUser, ...userData });
              }
            }
            return cb(insertError, null);
          }
        } else {
          // Update existing user
          console.log("Updating existing user from Google profile");
          try {
            // Use safe database operation for updating user
            const result = await safeDBOperation(async () => {
              return await collection.updateOne(
                { googleId: profile.id },
                {
                  $set: {
                    ...userData,
                    lastLogin: new Date(),
                  },
                },
              );
            });
            
            console.log("User updated:", result.modifiedCount);
            // Get the updated user to ensure we have all fields using safe operation
            const updatedUser = await safeDBOperation(async () => {
              return await collection.findOne({
                googleId: profile.id,
              });
            });
            return cb(null, updatedUser || userData);
          } catch (updateError) {
            console.error("Error updating user:", updateError);
            // Still return the user even if update failed
            return cb(null, user);
          }
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
  console.log("Session ID:", req.sessionID);
  console.log("User in session:", req.user);
  console.log("Is authenticated:", req.isAuthenticated());

  // Make user data available to templates
  res.locals.user = req.user || null;
  next();
});

// Middleware to make base URL available to all routes and templates
app.use((req, res, next) => {
  // Get the current base URL dynamically
  const currentBaseURL = getBaseURL(req);
  
  // Make base URL available to routes and templates
  req.baseURL = currentBaseURL;
  res.locals.baseURL = currentBaseURL;
  
  next();
});

// Set up EJS as view engine
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// Body parser middlewares must be before routes
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json()); // For JSON requests

// Serve static files
app.use(express.static(path.join(__dirname, "public"), { maxAge: 0 }));
app.use(
  "/css",
  express.static(path.join(__dirname, "public/css"), { maxAge: 0 }),
);
app.use(
  "/img",
  express.static(path.join(__dirname, "public/img"), { maxAge: 0 }),
);
app.use(
  "/js",
  express.static(path.join(__dirname, "public/js"), { maxAge: 0 }),
);

// Log static file serving details for debugging in Vercel
app.use((req, res, next) => {
  if (
    req.url.startsWith("/css") ||
    req.url.startsWith("/js") ||
    req.url.startsWith("/img")
  ) {
    console.log(
      `[STATIC] Serving: ${req.url}, Full path: ${path.join(__dirname, "public", req.url)}`,
    );
  }
  next();
});

// Add error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send("Something broke!");
});

// Body parser already set up earlier

// Routes
app.get("/", (req, res) => {
  console.log("Home route accessed");
  console.log("Is authenticated:", req.isAuthenticated());
  console.log("User in session:", req.user);

  // Check if user is in session
  if (req.isAuthenticated()) {
    console.log("User is authenticated, redirecting to dashboard");
    return res.redirect("/dashboard");
  } else {
    console.log("User is not authenticated, showing home page");
    return res.render("home.ejs", { title: "Home" });
  }
});

app.get("/dashboard", (req, res) => {
  console.log("Dashboard route accessed");
  console.log("Session ID:", req.sessionID);
  console.log("Is authenticated:", req.isAuthenticated());
  console.log("User in session:", req.user);
  console.log("Environment:", process.env.NODE_ENV);

  try {
    // Check if user is authenticated
    if (req.isAuthenticated() && req.user) {
      // Get success message if it exists
      const loginSuccess = req.session.loginSuccess;
      delete req.session.loginSuccess;

      return res.render("dashboard.ejs", {
        title: "Dashboard",
        user: req.user,
        loginSuccess: loginSuccess,
      });
    } else {
      console.log("User not authenticated, redirecting to signin");
      console.log("Authentication status:", req.isAuthenticated());
      console.log("User object:", req.user);
      return res.redirect("/auth/signin?error=authentication_required");
    }
  } catch (error) {
    console.error("Dashboard route error:", error);
    console.error("Dashboard route error stack:", error.stack);
    return res.status(500).render("signin.ejs", {
      title: "Sign In",
      error: "An error occurred accessing the dashboard. Please sign in again.",
    });
  }
});

// Room join route
app.get("/room/join", async (req, res) => {
  // Check if user is in session
  if (!req.user) {
    return res.redirect("/auth/signin");
  }

  const roomId = req.query.id;
  const roomPassword = req.query.password;

  if (!roomId) {
    return res.redirect("/dashboard");
  }

  try {
    // Check if room exists in MongoDB
    const roomData = await safeDBOperation(async () => {
      return await Room.findOne({ roomId: roomId.toString() });
    });

    const roomExists = activeRooms.has(roomId) || roomData;

    // If room doesn't exist yet but is stored in session (created by this user)
    const isCreator = roomId.toString() === req.session.lastCreatedRoomId;

    // Check if room requires password
    if (isCreator) {
      // Room creator doesn't need to enter password
      console.log(
        `Room creator ${req.user.fullname || "Anonymous"} is joining room ${roomId}`,
      );
    } else if (roomData && roomData.hasPassword) {
      // Room exists and requires password
      if (!roomPassword) {
        // Redirect back to dashboard with error
        return res.redirect(
          `/dashboard?error=Password required for room ${roomId}`,
        );
      }
      
      // Validate password
      if (roomPassword !== roomData.password) {
        return res.redirect(
          `/dashboard?error=Incorrect password for room ${roomId}`,
        );
      }
      
      console.log(
        `User ${req.user.fullname || "Anonymous"} is joining password-protected room ${roomId}`,
      );

      // Update last accessed time
      await safeDBOperation(async () => {
        await Room.updateOne(
          { roomId: roomId.toString() },
          { lastAccessed: new Date() }
        );
      });
    } else if (roomExists) {
      console.log(
        `User ${req.user.fullname || "Anonymous"} is joining room ${roomId}`,
      );
    } else {
      // Room doesn't exist
      return res.redirect(
        `/dashboard?error=Room ${roomId} does not exist`,
      );
    }

    // Redirect to the room
    res.redirect(`/room/${roomId}`);
  } catch (error) {
    console.error("Error accessing room:", error);
    return res.redirect(`/dashboard?error=Failed to access room ${roomId}`);
  }
});

// Room creation route
app.post("/room/create", async (req, res) => {
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

  try {
    // Generate a random room ID (6-digit number)
    const roomId = randomInteger(100000, 999999);

    // Create room data for MongoDB
    const isPrivateRoom = roomVisibility === "private";
    const roomData = {
      roomId: roomId.toString(),
      name: roomName,
      description: roomDescription || "",
      hasPassword: isPrivateRoom,
      password: isPrivateRoom ? roomPassword : null,
      createdBy: req.user.email,
      createdAt: new Date(),
      isActive: true,
      maxUsers: 10,
      lastAccessed: new Date()
    };

    // Save room to MongoDB
    await safeDBOperation(async () => {
      const room = new Room(roomData);
      await room.save();
    });

    console.log("Creating room:", roomData);

    // Store room information in session for later use
    req.session.roomName = roomName;
    req.session.roomLanguage = roomLanguage;
    req.session.roomDescription = roomDescription;
    req.session.roomVisibility = roomVisibility;

    // Store password if room is private
    if (isPrivateRoom && roomPassword) {
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
  } catch (error) {
    console.error("Error creating room:", error);
    return res.redirect("/dashboard?error=Failed to create room");
  }
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
      req, // Pass the request object to access user details in the template
    });
  } else {
    res.redirect("/auth/signin?error=authentication_required");
  }
});

app.get("/auth/signin", (req, res) => {
  // If user is already logged in, redirect to dashboard
  if (req.isAuthenticated()) {
    return res.redirect("/dashboard");
  }
  const error = req.query.error || null;
  const errorMessage = req.query.message || "Please sign in to continue";
  res.render("signin.ejs", {
    title: "Sign In",
    error: error ? errorMessage : null,
  });
});

app.get("/auth/signup", (req, res) => {
  // If user is already logged in, redirect to dashboard
  if (req.isAuthenticated()) {
    return res.redirect("/dashboard");
  }
  res.render("signup.ejs", { title: "Sign Up" });
});

app.get("/auth/forgot-password", (req, res) => {
  res.render("forgot-password.ejs", {
    title: "Forgot Password",
  });
});

// Add route for handling the forgot password form submission
app.post("/auth/forgot-password", (req, res) => {
  const email = req.body.email;

  // Basic validation
  if (!email) {
    return res.render("forgot-password.ejs", {
      title: "Forgot Password",
      error: "Email address is required",
      formData: { email: email },
    });
  }

  // Email format validation
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.render("forgot-password.ejs", {
      title: "Forgot Password",
      error: "Please enter a valid email address",
      formData: { email: email },
    });
  }

  // In a real application, this would send a password reset email
  // For this implementation, we'll just show a success message

  return res.render("forgot-password.ejs", {
    title: "Forgot Password",
    success:
      "If an account with that email exists, we've sent a password reset link.",
  });
});

// Google OAuth routes with improved logging
app.get(
  "/auth/google",
  (req, res, next) => {
    console.log("Starting Google OAuth process");
    // Store the return URL in session if provided
    if (req.query.returnTo) {
      req.session.returnTo = req.query.returnTo;
    }
    next();
  },
  passport.authenticate("google", {
    scope: ["profile", "email"],
    prompt: "select_account",
    accessType: "offline",
    includeGrantedScopes: true,
  }),
);

app.get(
  "/auth/google/callback",
  (req, res, next) => {
    console.log("Received Google OAuth callback", req.query);
    next();
  },
  passport.authenticate("google", {
    failureRedirect: "/auth/signin",
    failWithError: true,
  }),
  function (req, res) {
    console.log("Google auth successful, redirecting to dashboard");
    console.log("User authenticated:", req.user?.email);
    console.log("Session ID after Google auth:", req.sessionID);

    // Store auth type and timestamp in session
    req.session.authType = "google";
    req.session.authTime = new Date().toISOString();
    req.session.loginSuccess = true;

    // Get the return URL from session or default to dashboard
    const returnTo = req.session.returnTo || "/dashboard";
    delete req.session.returnTo;

    // Get the current base URL dynamically using request context
    // This ensures the redirect works correctly across all hosting environments:
    // - Vercel: https://code-collab-beta-v3.vercel.app/dashboard
    // - Localhost: http://localhost:3002/dashboard  
    // - Port forwarding: https://forwarded-domain.com/dashboard
    const currentBaseURL = getBaseURL(req);
    
    // Create the full redirect URL using the dynamically detected base URL
    const redirectURL = returnTo.startsWith('http') ? returnTo : `${currentBaseURL}${returnTo}`;
    console.log("Current base URL:", currentBaseURL);
    console.log("Redirecting to:", redirectURL);

    // Force session save before redirecting
    req.session.save((err) => {
      if (err) {
        console.error("Error saving session:", err);
      }
      res.redirect(redirectURL);
    });
  },
  function (err, req, res, next) {
    console.error("Google auth error:", err);
    
    // Get the current base URL dynamically
    const currentBaseURL = getBaseURL(req);
    
    // Store error message in session
    req.session.authError = err.message || "Google authentication failed";
    
    // Log specific error details for debugging
    if (err.oauthError) {
      console.error("OAuth error details:", err.oauthError);
    }
    
    console.log("Auth error, redirecting to signin with base URL:", currentBaseURL);
    
    res.redirect(
      "/auth/signin?error=google_auth_failed&message=" +
        encodeURIComponent(err.message || "Authentication failed"),
    );
  },
);

// Auth routes
app.post("/auth/signup", async (req, res) => {
  try {
    const data = {
      fullname: req.body.fullname,
      email: req.body.email,
      password: req.body.password,
      confirmPassword: req.body.confirmPassword,
      authType: "local", // Set auth type to local
      createdAt: new Date(),
    };

    // Basic validation
    if (
      !data.fullname ||
      !data.email ||
      !data.password ||
      !data.confirmPassword
    ) {
      return res.render("signup.ejs", {
        title: "Sign Up",
        error: "All fields are required",
        formData: data,
      });
    }

    // Email format validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(data.email)) {
      return res.render("signup.ejs", {
        title: "Sign Up",
        error: "Please enter a valid email address",
        formData: data,
      });
    }

    // Password length validation
    if (data.password.length < 6) {
      return res.render("signup.ejs", {
        title: "Sign Up",
        error: "Password must be at least 6 characters long",
        formData: data,
      });
    }

    // Use safe database operations for user checks
    const namecheck = await safeDBOperation(async () => {
      return await collection.findOne({ fullname: data.fullname });
    });
    
    const emailcheck = await safeDBOperation(async () => {
      return await collection.findOne({ email: data.email });
    });

    if (namecheck && emailcheck) {
      return res.render("signup.ejs", {
        title: "Sign Up",
        error: "Email and Full name already exist",
        formData: data,
      });
    } else if (namecheck) {
      return res.render("signup.ejs", {
        title: "Sign Up",
        error: "Full name already exists",
        formData: data,
      });
    } else if (emailcheck) {
      return res.render("signup.ejs", {
        title: "Sign Up",
        error: "Email already exists",
        formData: data,
      });
    } else {
      if (data.password === data.confirmPassword) {
        // Remove confirmPassword before storing in database
        delete data.confirmPassword;

        // Use safe database operation for user creation
        const result = await safeDBOperation(async () => {
          return await collection.insertOne(data);
        });
        
        console.log("User created:", data.email);

        // Log the user in automatically
        req.login(data, function (err) {
          if (err) {
            console.error("Error logging in after signup:", err);
            return res.redirect("/auth/signin");
          }
          console.log("User logged in after signup:", data.email);
          console.log("Session ID after signup:", req.sessionID);
          // Use relative redirect for local development to maintain session
          const redirectURL = "/dashboard";
          console.log("Redirecting after signup to:", redirectURL);
          return res.redirect(redirectURL);
        });
      } else {
        return res.render("signup.ejs", {
          title: "Sign Up",
          error: "Password and confirm password do not match",
          formData: data,
        });
      }
    }
  } catch (error) {
    console.error("Signup error:", error);
    return res.render("signup.ejs", {
      title: "Sign Up",
      error: "An error occurred during signup: " + error.message,
      formData: req.body,
    });
  }
});

// Fix signin route with proper redirection and Vercel error handling
app.post("/auth/signin", async (req, res, next) => {
  console.log("Login attempt for email:", req.body.email);
  console.log("Environment:", process.env.NODE_ENV);
  console.log("Request headers:", req.headers);

  if (!req.body.email || !req.body.password) {
    return res.render("signin.ejs", {
      title: "Sign In",
      error: "Email and password are required",
      formData: { email: req.body.email },
    });
  }

  // Wrap in try-catch for better error handling in serverless
  try {
    // Use passport authenticate directly
    passport.authenticate("local", async (err, user, info) => {
      try {
        if (err) {
          console.error("Authentication error:", err);
          console.error("Authentication error stack:", err.stack);
          return res.render("signin.ejs", {
            title: "Sign In",
            error: "An error occurred during authentication: " + err.message,
            formData: { email: req.body.email },
          });
        }

        if (!user) {
          // Authentication failed
          let errorMessage = "Invalid credentials";
          if (info && info.message) {
            errorMessage = info.message;
          }

          console.log("Authentication failed:", errorMessage);
          return res.render("signin.ejs", {
            title: "Sign In",
            error: errorMessage,
            formData: { email: req.body.email },
          });
        }

        // Authentication successful, log the user in
        req.login(user, (err) => {
          if (err) {
            console.error("Login error after authentication:", err);
            console.error("Login error stack:", err.stack);
            return res.render("signin.ejs", {
              title: "Sign In",
              error: "Login failed: " + err.message,
              formData: { email: req.body.email },
            });
          }

          console.log("User authenticated and logged in:", user.email);
          console.log("Session ID:", req.sessionID);
          console.log("Is authenticated:", req.isAuthenticated());
          console.log("User in session:", req.user);

          // Set a flash message in session
          req.session.loginSuccess = true;

          // Force session save in serverless environment
          req.session.save((saveErr) => {
            if (saveErr) {
              console.error("Session save error:", saveErr);
            }
            // Redirect to the dashboard after successful login
            // Use relative redirect for local development to maintain session
            const redirectURL = "/dashboard";
            console.log("Redirecting after login to:", redirectURL);
            return res.redirect(redirectURL);
          });
        });
      } catch (loginError) {
        console.error("Login process error:", loginError);
        return res.render("signin.ejs", {
          title: "Sign In",
          error: "An unexpected error occurred during login",
          formData: { email: req.body.email },
        });
      }
    })(req, res, next);
  } catch (outerError) {
    console.error("Outer signin error:", outerError);
    return res.render("signin.ejs", {
      title: "Sign In",
      error: "An unexpected server error occurred",
      formData: { email: req.body.email },
    });
  }
});

// Simple signup route that keeps users on the signup page

// Auth debug page to troubleshoot authentication issues
app.get("/auth/debug", async (req, res) => {
  // Allow debug in both development and production for troubleshooting
  // Comment out the production check temporarily for Vercel debugging
  // const isProduction = process.env.NODE_ENV === "production";
  // if (isProduction) {
  //   return res.redirect("/");
  // }

  // Check database connection status
  let databaseStatus = 'Unknown';
  let connectionDetails = {};
  
  try {
    // Import mongoose to check connection state
    const mongoose = await import('mongoose');
    connectionDetails = {
      readyState: mongoose.default.connection.readyState,
      readyStateText: ['disconnected', 'connected', 'connecting', 'disconnecting'][mongoose.default.connection.readyState] || 'unknown',
      host: mongoose.default.connection.host,
      name: mongoose.default.connection.name,
    };
    
    if (mongoose.default.connection.readyState === 1) {
      databaseStatus = 'Connected';
    } else if (mongoose.default.connection.readyState === 2) {
      databaseStatus = 'Connecting';
    } else {
      databaseStatus = 'Disconnected';
    }
  } catch (error) {
    databaseStatus = 'Error: ' + error.message;
  }

  const debugInfo = {
    isAuthenticated: req.isAuthenticated(),
    sessionID: req.sessionID,
    session: req.session,
    environment: process.env.NODE_ENV,
    vercelEnv: process.env.VERCEL_ENV,
    databaseStatus: databaseStatus,
    connectionDetails: connectionDetails,
    user: req.user
      ? {
          email: req.user.email,
          fullname: req.user.fullname,
          authType: req.user.authType,
          googleId: req.user.googleId,
          _id: req.user._id?.toString(),
        }
      : null,
    cookies: req.headers.cookie,
    headers: {
      host: req.headers.host,
      userAgent: req.headers["user-agent"],
      referer: req.headers.referer,
      'x-forwarded-proto': req.headers['x-forwarded-proto'],
      'x-forwarded-for': req.headers['x-forwarded-for'],
    },
  };

  res.render("auth-debug.ejs", {
    title: "Auth Debug",
    debugInfo: debugInfo,
  });
});

app.get("/auth/signout", (req, res, next) => {
  console.log("Logging out user:", req.user ? req.user.email : "No user");
  // Use passport's logout method with a callback for newer versions
  if (req.logout && typeof req.logout === "function") {
    req.logout(function (err) {
      if (err) {
        console.error("Error during logout:", err);
        return next(err);
      }

      // Then destroy the session
      req.session.destroy((err) => {
        if (err) {
          console.error("Error destroying session:", err);
          return next(err);
        }

        // Clear authentication cookies
        res.clearCookie("codecollab.sid");

        console.log("User logged out successfully");
        return res.redirect("/");
      });
    });
  } else {
    // Fallback for older versions
    req.logout();
    req.session.destroy((err) => {
      if (err) {
        console.error("Error destroying session:", err);
        return next(err);
      }

      res.clearCookie("codecollab.sid");
      return res.redirect("/");
    });
  }
});

// Room status API endpoint
app.get("/api/rooms/status", async (req, res) => {
  // Check if user is authenticated
  if (!req.user) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const roomsStatus = [];

    // Get all rooms from MongoDB
    const allRooms = await safeDBOperation(async () => {
      return await Room.find({ isActive: true }).sort({ lastAccessed: -1 });
    });

    // Add active rooms (currently connected users)
    for (const [roomId, users] of activeRooms.entries()) {
      const roomData = allRooms.find(r => r.roomId === roomId.toString());
      
      roomsStatus.push({
        roomId,
        name: roomData?.name || `Room ${roomId}`,
        userCount: users.size,
        isPasswordProtected: roomData?.hasPassword || false,
        isActive: true,
        language: 'javascript', // Default since we removed language field
        createdBy: roomData?.createdBy || 'Unknown',
        users: Array.from(users.values()).map((user) => ({
          userId: user.userId,
          username: user.username,
          picture: user.picture,
        })),
      });
    }

    // Add created but not yet active rooms
    for (const roomData of allRooms) {
      if (!activeRooms.has(roomData.roomId)) {
        roomsStatus.push({
          roomId: roomData.roomId,
          name: roomData.name,
          userCount: 0,
          isPasswordProtected: roomData.hasPassword,
          isActive: false,
          language: 'javascript', // Default since we removed language field
          createdBy: roomData.createdBy,
          users: [],
        });
      }
    }

    res.json({
      activeRooms: roomsStatus,
      totalRooms: roomsStatus.length,
      totalUsers: [...activeRooms.values()].reduce(
        (total, users) => total + users.size,
        0,
      ),
    });
  } catch (error) {
    console.error("Error fetching rooms status:", error);
    res.status(500).json({ error: "Failed to fetch rooms status" });
  }
});

// Add authentication status endpoint for debugging
app.get("/api/auth-status", (req, res) => {
  try {
    const authStatus = {
      timestamp: new Date().toISOString(),
      environment: process.env.NODE_ENV,
      vercelEnv: process.env.VERCEL_ENV,
      isAuthenticated: req.isAuthenticated(),
      hasUser: !!req.user,
      sessionID: req.sessionID,
      databaseConnected: !!collection,
      userAgent: req.headers['user-agent'],
      cookies: !!req.headers.cookie,
      sessionCookie: req.headers.cookie ? req.headers.cookie.includes('codecollab.sid') : false,
    };

    if (req.user) {
      authStatus.user = {
        email: req.user.email,
        authType: req.user.authType,
        hasGoogleId: !!req.user.googleId,
      };
    }

    res.json(authStatus);
  } catch (error) {
    console.error("Auth status check error:", error);
    res.status(500).json({
      error: "Failed to check auth status",
      message: error.message,
      timestamp: new Date().toISOString(),
    });
  }
});

// Add URL detection debug endpoint
app.get("/api/url-debug", (req, res) => {
  try {
    const currentBaseURL = getBaseURL(req);
    
    const urlDebugInfo = {
      timestamp: new Date().toISOString(),
      detectedBaseURL: currentBaseURL,
      staticBaseURL: baseURL,
      googleCallbackURL: googleCallbackURL,
      environment: {
        NODE_ENV: process.env.NODE_ENV,
        VERCEL_ENV: process.env.VERCEL_ENV,
        VERCEL_URL: process.env.VERCEL_URL,
        CODESPACE_NAME: process.env.CODESPACE_NAME,
        GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN: process.env.GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN,
        PORT: process.env.PORT,
        HTTPS: process.env.HTTPS,
        BASE_URL: process.env.BASE_URL,
        FORWARDED_URL: process.env.FORWARDED_URL,
        GOOGLE_CALLBACK_URL: process.env.GOOGLE_CALLBACK_URL,
      },
      flags: {
        isVercelEnvironment: isVercelEnvironment,
        isVercelProduction: isVercelProduction,
        isCodespaces: isCodespaces,
        isCustomPort: isCustomPort,
      },
      requestHeaders: {
        host: req.headers.host,
        'x-forwarded-host': req.headers['x-forwarded-host'],
        'x-forwarded-proto': req.headers['x-forwarded-proto'],
        'x-forwarded-for': req.headers['x-forwarded-for'],
        'user-agent': req.headers['user-agent'],
        origin: req.headers.origin,
        referer: req.headers.referer,
      },
      requestInfo: {
        protocol: req.protocol,
        secure: req.secure,
        hostname: req.hostname,
        originalUrl: req.originalUrl,
        baseUrl: req.baseUrl,
        url: req.url,
      }
    };

    res.json(urlDebugInfo);
  } catch (error) {
    console.error("URL debug error:", error);
    res.status(500).json({
      error: "Failed to get URL debug info",
      message: error.message,
      timestamp: new Date().toISOString(),
    });
  }
});

// Vercel debug page route
app.get("/vercel-debug", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "vercel-debug.html"));
});

// Socket.IO setup for real-time collaboration
io.on("connection", (socket) => {
  console.log("A user connected:", socket.id);

  // Generate a unique color for this user
  const getColorForUser = (userId) => {
    if (!userColors.has(userId)) {
      const colors = [
        "#FF5252",
        "#FF4081",
        "#E040FB",
        "#7C4DFF",
        "#536DFE",
        "#448AFF",
        "#40C4FF",
        "#18FFFF",
        "#64FFDA",
        "#69F0AE",
        "#B2FF59",
        "#EEFF41",
        "#FFFF00",
        "#FFD740",
        "#FFAB40",
        "#FF6E40",
      ];
      userColors.set(userId, colors[Math.floor(Math.random() * colors.length)]);
    }
    return userColors.get(userId);
  };

  // Handle joining a room
  socket.on("join_room", (roomData) => {
    const { roomId, userId, username, picture, language } = roomData;

    console.log(
      `User ${username} (${socket.id}) attempting to join room ${roomId}`,
    );

    // Create room if it doesn't exist
    if (!activeRooms.has(roomId)) {
      console.log(`Creating new room: ${roomId}`);
      activeRooms.set(roomId, new Map());
      // Initialize room properties
      activeRooms.get(roomId).language = language || "javascript";
      activeRooms.get(roomId).createdAt = new Date().toISOString();
      activeRooms.get(roomId).createdBy = userId;
    }

    // Get the users map for this room
    const roomUsers = activeRooms.get(roomId);

    // Check if user is already in the room with another socket
    let userAlreadyInRoom = false;
    for (const [existingSocketId, userData] of roomUsers.entries()) {
      if (userData.userId === userId) {
        userAlreadyInRoom = true;
        if (existingSocketId !== socket.id) {
          // Remove the old socket entry
          roomUsers.delete(existingSocketId);
        }
      }
    }

    // Assign a color to the user if they don't have one
    const userColor = getColorForUser(userId);

    // Add user to the room with their socket id
    roomUsers.set(socket.id, {
      userId,
      username,
      picture,
      socketId: socket.id,
      joinedAt: new Date(),
      color: userColor,
    });

    // Join the Socket.IO room
    socket.join(roomId);

    // Send current cursor positions to the new user
    const cursors = [];
    for (const userData of roomUsers.values()) {
      if (userData.cursorPosition && userData.socketId !== socket.id) {
        cursors.push({
          userId: userData.userId,
          username: userData.username,
          position: userData.cursorPosition,
          color: userData.color || getColorForUser(userData.userId),
        });
      }
    }
    
    if (cursors.length > 0) {
      socket.emit("cursor_positions", { cursors });
    }

    // Notify all users in the room about the new user
    io.to(roomId).emit("user_joined", {
      userId,
      username,
      picture,
      socketId: socket.id,
      userCount: roomUsers.size,
      language: activeRooms.get(roomId).language,
      timestamp: Date.now(),
      color: userColor,
    });

    console.log(
      `User ${username} (${socket.id}) joined room ${roomId} with ${roomUsers.size} total users`,
    );
  });

  // Handle code changes
  socket.on("code_change", (data) => {
    const { roomId, code, language, userId, username, cursorPosition } = data;

    // Validate data
    if (!roomId || !userId || typeof code !== "string") {
      console.log(`Invalid code data from ${username || userId}`);
      return;
    }

    // Broadcast code change to all other users in the room
    socket.to(roomId).emit("code_updated", {
      code,
      language,
      userId,
      username,
      timestamp: Date.now(),
    });
  });

  // Handle language changes
  socket.on("language_change", (data) => {
    const { roomId, language, userId, username } = data;

    // Validate data
    if (!roomId || !userId || !language) {
      console.log(`Invalid language data from ${username || userId}`);
      return;
    }

    // Update room language preference
    if (activeRooms.has(roomId)) {
      activeRooms.get(roomId).language = language;

      // Broadcast language change to all users in the room
      io.to(roomId).emit("language_changed", {
        language,
        userId,
        username,
        timestamp: Date.now(),
      });
    }
  });

  // Handle cursor position updates
  socket.on("cursor_move", (data) => {
    const { roomId, userId, username, cursorPosition } = data;

    // Validate data
    if (!roomId || !userId || !cursorPosition) {
      return;
    }

    // Ensure room exists
    if (!activeRooms.has(roomId)) {
      return;
    }

    const roomUsers = activeRooms.get(roomId);
    const userData = roomUsers.get(socket.id);

    if (!userData) {
      return;
    }

    // Store cursor position in user data
    userData.cursorPosition = cursorPosition;

    // Get user's color
    const color = userData.color || getColorForUser(userId);

    // Broadcast cursor position to all other users in the room
    socket.to(roomId).emit("cursor_updated", {
      userId,
      username,
      cursorPosition,
      color,
      timestamp: Date.now(),
    });
  });

  // Handle requests for cursor positions
  socket.on("request_cursor_positions", (data) => {
    const { roomId } = data;

    if (!roomId || !activeRooms.has(roomId)) {
      return;
    }

    const roomUsers = activeRooms.get(roomId);

    // Collect all cursor positions in the room
    const cursors = [];
    for (const userData of roomUsers.values()) {
      if (userData.cursorPosition) {
        cursors.push({
          userId: userData.userId,
          username: userData.username,
          position: userData.cursorPosition,
          color: userData.color || getColorForUser(userData.userId),
        });
      }
    }

    // Send cursor positions to the requesting client
    socket.emit("cursor_positions", { cursors });
  });

  // Handle chat messages
  socket.on("send_message", (data) => {
    const { roomId, userId, username, picture, message, timestamp } = data;

    // Validate message
    if (!roomId || !userId || !message) {
      return;
    }

    // Simple sanitization - limit message length
    const sanitizedMessage = message.slice(0, 1000).trim();
    if (!sanitizedMessage) {
      return;
    }

    // Broadcast message to all users in the room
    io.to(roomId).emit("new_message", {
      userId,
      username,
      picture,
      message: sanitizedMessage,
      timestamp: timestamp || Date.now(),
    });
  });

  // Handle room name changes
  socket.on("rename_room", (data) => {
    const { roomId, name, userId } = data;

    if (!roomId || !name || !userId) {
      return;
    }

    // Ensure room exists
    if (activeRooms.has(roomId)) {
      const room = activeRooms.get(roomId);

      // Only the room creator can rename it
      if (room.createdBy === userId) {
        activeRooms.get(roomId).name = name;

        // Broadcast room name change
        io.to(roomId).emit("room_renamed", {
          roomId,
          name,
          userId,
          timestamp: Date.now(),
        });
      }
    }
  });

  // Handle code execution requests
  socket.on("run_code", (data) => {
    const { roomId, code, language, userId, username, fileName } = data;

    if (!roomId || !code || !language) {
      return;
    }

    // In a real implementation, you would use a sandboxed environment
    // to execute the code securely. For this example, we'll simulate a response.
    console.log(
      `Running ${language} code for user ${username} in room ${roomId}`,
    );

    // Simulate code execution after a delay
    setTimeout(() => {
      let result, error;

      // Simple simulation of execution results
      try {
        if (language.toLowerCase().includes("javascript")) {
          // For demo purposes only - this is not secure!
          // In production, use proper sandboxing solutions
          result =
            "Console output would appear here\n> JavaScript execution complete";
        } else if (language.toLowerCase().includes("python")) {
          result = `Python 3.9.5 (default, May 4 2021, 03:36:27) \n[Clang 12.0.0 (clang-1200.0.32.29)] on darwin\n> Output: Hello, world!\n> Python execution complete`;
        } else {
          result = `Executed ${language} code from ${fileName} successfully.\n> Output would appear here\n> Execution complete`;
        }
      } catch (err) {
        error = err.message;
      }

      // Send result back to the room
      io.to(roomId).emit("code_result", {
        result,
        error,
        language,
        userId,
        timestamp: Date.now(),
      });
    }, 1000);
  });

  // Handle bash command execution
  socket.on("bash_command", (data) => {
    const { roomId, command, userId, username } = data;

    if (!roomId || !command) {
      return;
    }

    console.log(
      `Executing bash command '${command}' from user ${username} in room ${roomId}`,
    );

    // Add to execution queue
    bashQueue.push({
      roomId,
      command,
      userId,
      username,
      timestamp: Date.now(),
    });

    // Process queue if not already processing
    if (!processingBash) {
      processBashQueue();
    }
  });

  // Handle new file creation
  socket.on("new_file", (data) => {
    const { roomId, userId, username, file } = data;

    if (!roomId || !userId || !file) {
      return;
    }

    // Broadcast to all other users in the room
    socket.to(roomId).emit("file_added", {
      userId,
      username,
      file,
      timestamp: Date.now(),
    });
  });

  // Handle file switching
  socket.on("switch_file", (data) => {
    const { roomId, userId, username, fileIndex } = data;

    if (!roomId || !userId || fileIndex === undefined) {
      return;
    }

    // This would be used if we wanted to track which file each user is viewing
    // For now, we're just broadcasting the event for potential future features
    socket.to(roomId).emit("file_switched", {
      userId,
      username,
      fileIndex,
      timestamp: Date.now(),
    });
  });

  // Handle file save events
  socket.on("file_saved", (data) => {
    const { roomId, userId, username, fileName, fileIndex } = data;

    if (!roomId || !userId || !fileName) {
      return;
    }

    // Broadcast file save event to other users
    socket.to(roomId).emit("file_saved", {
      userId,
      username,
      fileName,
      fileIndex,
      timestamp: Date.now(),
    });
  });

  // Handle file close events
  socket.on("file_closed", (data) => {
    const { roomId, userId, username, fileName, fileIndex } = data;

    if (!roomId || !userId || !fileName) {
      return;
    }

    // Broadcast file close event to other users
    socket.to(roomId).emit("file_closed", {
      userId,
      username,
      fileName,
      fileIndex,
      timestamp: Date.now(),
    });
  });

  // Handle disconnection
  socket.on("disconnect", () => {
    console.log("User disconnected:", socket.id);

    // Find which room the user was in
    for (const [roomId, users] of activeRooms.entries()) {
      if (users.has(socket.id)) {
        const userData = users.get(socket.id);
        if (!userData) continue;

        const { userId, username } = userData;

        // Remove this socket
        users.delete(socket.id);

        // Check if user has other active sockets in the room
        let hasOtherSockets = false;
        for (const user of users.values()) {
          if (user.userId === userId) {
            hasOtherSockets = true;
            break;
          }
        }

        if (!hasOtherSockets) {
          // If the room is empty, remove it
          if (users.size === 0) {
            activeRooms.delete(roomId);
          } else {
            // Notify others that the user left
            io.to(roomId).emit("user_left", {
              userId,
              username,
              userCount: users.size,
              timestamp: Date.now(),
            });
          }
        }

        break; // Exit the loop once we've found and processed the room
      }
    }
  });
});

// Process bash commands sequentially to prevent overload
function processBashQueue() {
  if (bashQueue.length === 0) {
    processingBash = false;
    return;
  }

  processingBash = true;
  const nextCommand = bashQueue.shift();

  // Simulate bash command execution
  console.log(`Processing bash command: ${nextCommand.command}`);

  setTimeout(() => {
    let result, error;

    try {
      // Simple simulation of various bash commands
      const cmd = nextCommand.command.toLowerCase();

      if (cmd === "ls" || cmd.startsWith("ls ")) {
        result = "file1.js\nfile2.py\nREADME.md\npackage.json";
      } else if (cmd === "pwd") {
        result = "/home/user/project";
      } else if (cmd === "whoami") {
        result = "codecollab-user";
      } else if (cmd === "date") {
        result = new Date().toString();
      } else if (cmd.startsWith("echo ")) {
        result = cmd.substring(5);
      } else if (cmd === "help" || cmd === "man") {
        result = "Available commands: ls, pwd, whoami, date, echo, help";
      } else {
        result = `Command '${nextCommand.command}' executed (simulated)`;
      }
    } catch (err) {
      error = `Error executing command: ${err.message}`;
    }

    // Send result back to the room
    io.to(nextCommand.roomId).emit("bash_result", {
      result,
      error,
      command: nextCommand.command,
      userId: nextCommand.userId,
      timestamp: Date.now(),
    });

    // Process next command after a small delay
    setTimeout(processBashQueue, 100);
  }, 500);
}

// Error handling for Vercel serverless environment
const handleServerError = (err) => {
  console.error("Server error:", err);
  // In production, you might want to log to a service
  if (process.env.NODE_ENV === "production") {
    // Log to your preferred service
    console.error("Production server error:", err.message, err.stack);
  }
};

// Start the server only if not in serverless environment
if (!process.env.VERCEL_ENV && !process.env.AWS_LAMBDA_FUNCTION_NAME) {
  httpServer
    .listen(port, () => {
      console.log("✅ CodeCollab Server Started Successfully!");
      console.log("📍 Server listening on port:", port);
      console.log("🌐 Base URL:", baseURL);
      console.log("🔗 Google OAuth Callback:", googleCallbackURL);
      console.log("🏠 Dashboard URL:", `${baseURL}/dashboard`);
      console.log("🔐 Sign In URL:", `${baseURL}/auth/signin`);
      console.log("📊 Health Check:", `${baseURL}/api/health`);
      console.log("🐛 URL Debug:", `${baseURL}/api/url-debug`);
      console.log("═".repeat(60));
    })
    .on("error", handleServerError);
} else {
  console.log("✅ CodeCollab Serverless Environment Initialized");
  console.log("🌐 Base URL:", baseURL);
  console.log("🔗 Google OAuth Callback:", googleCallbackURL);
  console.log("📊 Health Check endpoint available at: /api/health");
  console.log("🐛 URL Debug endpoint available at: /api/url-debug");
  console.log("═".repeat(60));
}

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

// Log specific CSS file path for verification
if (fs.existsSync(path.join(__dirname, "public/css/ios-style.css"))) {
  console.log("CSS file ios-style.css exists and is accessible");
  console.log("Full path:", path.join(__dirname, "public/css/ios-style.css"));
  const stats = fs.statSync(path.join(__dirname, "public/css/ios-style.css"));
  console.log("File size:", stats.size, "bytes");
}
console.log(
  "CSS file exists:",
  fs.existsSync(path.join(__dirname, "public/css/ios-style.css")),
);

// Handle unhandled promise rejections
process.on("unhandledRejection", (reason, promise) => {
  console.error("Unhandled Rejection at:", promise, "reason:", reason);
  // In a production environment, you may want to do additional logging
});
