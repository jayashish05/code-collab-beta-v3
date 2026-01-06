import express from "express";
import dotenv from "dotenv";

// Load environment variables FIRST before anything else
dotenv.config();

import { collection, Room, VoiceChat, safeDBOperation, ensureDBConnection, connectDB, trackUserActivity, startCodingSession, updateCodingSession, endCodingSession, trackCodeExecution, saveRoomCode, loadRoomCode, saveRoomFile, autoSaveRoomData } from "./config.js";
import bodyParser from "body-parser";
import path from "path";
import { fileURLToPath } from "url";
import * as fs from "fs";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as GoogleStrategy } from "passport-google-oauth2";
import { Strategy as GitHubStrategy } from "passport-github2";
import session from "express-session";
import randomInteger from "random-int";
import { v4 as uuidv4 } from "uuid";
import { createServer } from "http";
import { Server } from "socket.io";
import crypto from "crypto"; // Add crypto import for session ID generation
import { exec, spawn } from "child_process"; // Add for code execution
import { promisify } from "util"; // Add for promisifying exec
import { GoogleGenerativeAI } from "@google/generative-ai"; // Add Gemini AI integration
import Razorpay from "razorpay"; // Add Razorpay for payments
import nodemailer from "nodemailer"; // Add email functionality for password reset

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
console.log('GITHUB_CLIENT_ID:', process.env.GITHUB_CLIENT_ID ? 'Set' : 'Not set');
console.log('GITHUB_CLIENT_SECRET:', process.env.GITHUB_CLIENT_SECRET ? 'Set' : 'Not set');
console.log('GEMINI_API_KEY:', process.env.GEMINI_API_KEY ? 'Set' : 'Not set');
console.log('RAZORPAY_KEY_ID:', process.env.RAZORPAY_KEY_ID ? 'Set' : 'Not set');
console.log('RAZORPAY_KEY_SECRET:', process.env.RAZORPAY_KEY_SECRET ? 'Set' : 'Not set');
console.log('EMAIL_USER:', process.env.EMAIL_USER ? 'Set' : 'Not set');
console.log('EMAIL_PASS:', process.env.EMAIL_PASS ? 'Set' : 'Not set');

// Initialize Razorpay
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});

// Configure nodemailer for sending emails
let transporter = null;

try {
  if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
    transporter = nodemailer.createTransport({
      service: 'gmail', // You can change this to your email service
      auth: {
        user: process.env.EMAIL_USER, // Your email
        pass: process.env.EMAIL_PASS  // Your app password (not regular password)
      }
    });
    console.log('Email transporter configured successfully');
  } else {
    console.warn('Email configuration missing - forgot password emails will not be sent');
  }
} catch (error) {
  console.error('Failed to configure email transporter:', error);
}

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

// Promisify exec for better async handling
const execAsync = promisify(exec);

// Code execution function with support for multiple languages
async function executeCode(code, language, fileName = 'temp') {
  const startTime = Date.now();
  
  try {
    let result;
    const normalizedLanguage = language.toLowerCase();
    
    // Create a temporary directory for code execution
    const tempDir = path.join(__dirname, 'temp');
    if (!fs.existsSync(tempDir)) {
      fs.mkdirSync(tempDir, { recursive: true });
    }
    
    // Generate unique filename to avoid conflicts
    const uniqueId = Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    
    switch (normalizedLanguage) {
      case 'javascript':
      case 'js':
        result = await executeJavaScript(code, tempDir, uniqueId);
        break;
        
      case 'python':
      case 'py':
        result = await executePython(code, tempDir, uniqueId);
        break;
        
      case 'java':
        result = await executeJava(code, tempDir, uniqueId, fileName);
        break;
        
      case 'cpp':
      case 'c++':
        result = await executeCpp(code, tempDir, uniqueId);
        break;
        
      case 'c':
        result = await executeC(code, tempDir, uniqueId);
        break;
        
      case 'go':
        result = await executeGo(code, tempDir, uniqueId);
        break;
        
      case 'rust':
        result = await executeRust(code, tempDir, uniqueId);
        break;
        
      case 'php':
        result = await executePhp(code, tempDir, uniqueId);
        break;
        
      case 'ruby':
        result = await executeRuby(code, tempDir, uniqueId);
        break;
        
      case 'bash':
      case 'shell':
        result = await executeBash(code, tempDir, uniqueId);
        break;
        
      default:
        throw new Error(`Language '${language}' is not supported yet. Supported languages: JavaScript, Python, Java, C++, C, Go, Rust, PHP, Ruby, Bash`);
    }
    
    const executionTime = Date.now() - startTime;
    
    return {
      output: result.output,
      error: result.error,
      executionTime: `${executionTime}ms`
    };
    
  } catch (error) {
    const executionTime = Date.now() - startTime;
    return {
      output: null,
      error: error.message,
      executionTime: `${executionTime}ms`
    };
  }
}

// JavaScript execution
async function executeJavaScript(code, tempDir, uniqueId) {
  const filePath = path.join(tempDir, `${uniqueId}.js`);
  fs.writeFileSync(filePath, code);
  
  try {
    const { stdout, stderr } = await execAsync(`node "${filePath}"`, {
      timeout: 10000, // 10 second timeout
      cwd: tempDir
    });
    
    // Clean up
    fs.unlinkSync(filePath);
    
    return {
      output: stdout || 'Code executed successfully (no output)',
      error: stderr || null
    };
  } catch (error) {
    // Clean up even if execution failed
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }
    
    return {
      output: null,
      error: error.message || error.stderr || 'JavaScript execution failed'
    };
  }
}

// Python execution
async function executePython(code, tempDir, uniqueId) {
  const filePath = path.join(tempDir, `${uniqueId}.py`);
  fs.writeFileSync(filePath, code);
  
  try {
    const { stdout, stderr } = await execAsync(`python3 "${filePath}"`, {
      timeout: 15000, // 15 second timeout
      cwd: tempDir
    });
    
    // Clean up
    fs.unlinkSync(filePath);
    
    return {
      output: stdout || 'Code executed successfully (no output)',
      error: stderr || null
    };
  } catch (error) {
    // Clean up even if execution failed
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }
    
    // Try python instead of python3
    try {
      const { stdout, stderr } = await execAsync(`python "${filePath}"`, {
        timeout: 15000,
        cwd: tempDir
      });
      
      return {
        output: stdout || 'Code executed successfully (no output)',
        error: stderr || null
      };
    } catch (fallbackError) {
      return {
        output: null,
        error: 'Python execution failed. Make sure Python is installed on the system.'
      };
    }
  }
}

// Java execution
async function executeJava(code, tempDir, uniqueId, fileName) {
  // Extract class name from code or use fileName
  const classNameMatch = code.match(/public\s+class\s+(\w+)/);
  const className = classNameMatch ? classNameMatch[1] : fileName.replace(/\.(java|class)$/, '');
  
  const filePath = path.join(tempDir, `${className}.java`);
  fs.writeFileSync(filePath, code);
  
  try {
    // Compile
    const { stderr: compileError } = await execAsync(`javac "${filePath}"`, {
      timeout: 10000,
      cwd: tempDir
    });
    
    if (compileError) {
      throw new Error(`Compilation failed: ${compileError}`);
    }
    
    // Execute
    const { stdout, stderr } = await execAsync(`java -cp "${tempDir}" ${className}`, {
      timeout: 15000,
      cwd: tempDir
    });
    
    // Clean up
    const classFile = path.join(tempDir, `${className}.class`);
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    if (fs.existsSync(classFile)) fs.unlinkSync(classFile);
    
    return {
      output: stdout || 'Code executed successfully (no output)',
      error: stderr || null
    };
  } catch (error) {
    // Clean up
    const classFile = path.join(tempDir, `${className}.class`);
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    if (fs.existsSync(classFile)) fs.unlinkSync(classFile);
    
    return {
      output: null,
      error: error.message || 'Java execution failed. Make sure Java JDK is installed.'
    };
  }
}

// C++ execution
async function executeCpp(code, tempDir, uniqueId) {
  const filePath = path.join(tempDir, `${uniqueId}.cpp`);
  const exePath = path.join(tempDir, `${uniqueId}_cpp`);
  fs.writeFileSync(filePath, code);
  
  try {
    // Compile
    const { stderr: compileError } = await execAsync(`g++ "${filePath}" -o "${exePath}"`, {
      timeout: 15000,
      cwd: tempDir
    });
    
    if (compileError) {
      throw new Error(`Compilation failed: ${compileError}`);
    }
    
    // Execute
    const { stdout, stderr } = await execAsync(`"${exePath}"`, {
      timeout: 10000,
      cwd: tempDir
    });
    
    // Clean up
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    if (fs.existsSync(exePath)) fs.unlinkSync(exePath);
    
    return {
      output: stdout || 'Code executed successfully (no output)',
      error: stderr || null
    };
  } catch (error) {
    // Clean up
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    if (fs.existsSync(exePath)) fs.unlinkSync(exePath);
    
    return {
      output: null,
      error: error.message || 'C++ execution failed. Make sure g++ compiler is installed.'
    };
  }
}

// C execution
async function executeC(code, tempDir, uniqueId) {
  const filePath = path.join(tempDir, `${uniqueId}.c`);
  const exePath = path.join(tempDir, `${uniqueId}_c`);
  fs.writeFileSync(filePath, code);
  
  try {
    // Compile
    const { stderr: compileError } = await execAsync(`gcc "${filePath}" -o "${exePath}"`, {
      timeout: 15000,
      cwd: tempDir
    });
    
    if (compileError) {
      throw new Error(`Compilation failed: ${compileError}`);
    }
    
    // Execute
    const { stdout, stderr } = await execAsync(`"${exePath}"`, {
      timeout: 10000,
      cwd: tempDir
    });
    
    // Clean up
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    if (fs.existsSync(exePath)) fs.unlinkSync(exePath);
    
    return {
      output: stdout || 'Code executed successfully (no output)',
      error: stderr || null
    };
  } catch (error) {
    // Clean up
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    if (fs.existsSync(exePath)) fs.unlinkSync(exePath);
    
    return {
      output: null,
      error: error.message || 'C execution failed. Make sure gcc compiler is installed.'
    };
  }
}

// Go execution
async function executeGo(code, tempDir, uniqueId) {
  const filePath = path.join(tempDir, `${uniqueId}.go`);
  fs.writeFileSync(filePath, code);
  
  try {
    const { stdout, stderr } = await execAsync(`go run "${filePath}"`, {
      timeout: 15000,
      cwd: tempDir
    });
    
    // Clean up
    fs.unlinkSync(filePath);
    
    return {
      output: stdout || 'Code executed successfully (no output)',
      error: stderr || null
    };
  } catch (error) {
    // Clean up
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    
    return {
      output: null,
      error: error.message || 'Go execution failed. Make sure Go is installed.'
    };
  }
}

// Rust execution
async function executeRust(code, tempDir, uniqueId) {
  const filePath = path.join(tempDir, `${uniqueId}.rs`);
  const exePath = path.join(tempDir, `${uniqueId}_rust`);
  fs.writeFileSync(filePath, code);
  
  try {
    // Compile
    const { stderr: compileError } = await execAsync(`rustc "${filePath}" -o "${exePath}"`, {
      timeout: 20000,
      cwd: tempDir
    });
    
    if (compileError) {
      throw new Error(`Compilation failed: ${compileError}`);
    }
    
    // Execute
    const { stdout, stderr } = await execAsync(`"${exePath}"`, {
      timeout: 10000,
      cwd: tempDir
    });
    
    // Clean up
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    if (fs.existsSync(exePath)) fs.unlinkSync(exePath);
    
    return {
      output: stdout || 'Code executed successfully (no output)',
      error: stderr || null
    };
  } catch (error) {
    // Clean up
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    if (fs.existsSync(exePath)) fs.unlinkSync(exePath);
    
    return {
      output: null,
      error: error.message || 'Rust execution failed. Make sure Rust is installed.'
    };
  }
}

// PHP execution
async function executePhp(code, tempDir, uniqueId) {
  const filePath = path.join(tempDir, `${uniqueId}.php`);
  fs.writeFileSync(filePath, code);
  
  try {
    const { stdout, stderr } = await execAsync(`php "${filePath}"`, {
      timeout: 10000,
      cwd: tempDir
    });
    
    // Clean up
    fs.unlinkSync(filePath);
    
    return {
      output: stdout || 'Code executed successfully (no output)',
      error: stderr || null
    };
  } catch (error) {
    // Clean up
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    
    return {
      output: null,
      error: error.message || 'PHP execution failed. Make sure PHP is installed.'
    };
  }
}

// Ruby execution
async function executeRuby(code, tempDir, uniqueId) {
  const filePath = path.join(tempDir, `${uniqueId}.rb`);
  fs.writeFileSync(filePath, code);
  
  try {
    const { stdout, stderr } = await execAsync(`ruby "${filePath}"`, {
      timeout: 10000,
      cwd: tempDir
    });
    
    // Clean up
    fs.unlinkSync(filePath);
    
    return {
      output: stdout || 'Code executed successfully (no output)',
      error: stderr || null
    };
  } catch (error) {
    // Clean up
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    
    return {
      output: null,
      error: error.message || 'Ruby execution failed. Make sure Ruby is installed.'
    };
  }
}

// Bash execution
async function executeBash(code, tempDir, uniqueId) {
  const filePath = path.join(tempDir, `${uniqueId}.sh`);
  fs.writeFileSync(filePath, code);
  
  try {
    const { stdout, stderr } = await execAsync(`bash "${filePath}"`, {
      timeout: 10000,
      cwd: tempDir
    });
    
    // Clean up
    fs.unlinkSync(filePath);
    
    return {
      output: stdout || 'Code executed successfully (no output)',
      error: stderr || null
    };
  } catch (error) {
    // Clean up
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    
    return {
      output: null,
      error: error.message || 'Bash execution failed.'
    };
  }
}

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

// Enhanced session configuration for serverless and localhost
app.use(
  session({
    secret: process.env.SESSION_SECRET || "codecollab_dev_secret_replace_in_production_12345",
    resave: false,
    saveUninitialized: false,
    rolling: true, // Reset expiration on activity
    cookie: {
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
      httpOnly: true,
      secure: false, // Always false for local development
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
  }),
);

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

// Configure Google Strategy - Enhanced callback URL detection
const isVercelProduction = process.env.VERCEL_ENV === 'production' || 
                          process.env.VERCEL_URL || 
                          process.env.NODE_ENV === 'production';

// Check if we're running in a dev tunnel environment
const isDevTunnel = process.env.CODESPACE_NAME || 
                   process.env.GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN ||
                   (process.env.PORT && process.env.PORT !== '3002');

// Determine the appropriate callback URL and base URL based on environment
let googleCallbackURL;
let baseURL;

if (process.env.GOOGLE_CALLBACK_URL) {
  // Use explicitly set callback URL (highest priority)
  googleCallbackURL = process.env.GOOGLE_CALLBACK_URL;
  // Extract base URL from callback URL
  baseURL = googleCallbackURL.replace('/auth/google/callback', '');
} else if (isVercelProduction) {
  // Vercel production environment
  googleCallbackURL = "https://code-collab-beta-v3.vercel.app/auth/google/callback";
  baseURL = "https://code-collab-beta-v3.vercel.app";
} else {
  // Development environment - check if we're using HTTPS or HTTP
  const protocol = process.env.HTTPS === 'true' ? 'https' : 'http';
  googleCallbackURL = `${protocol}://localhost:3002/auth/google/callback`;
  baseURL = `${protocol}://localhost:3002`;
}

console.log("Environment detection:");
console.log("- VERCEL_ENV:", process.env.VERCEL_ENV);
console.log("- VERCEL_URL:", process.env.VERCEL_URL);
console.log("- NODE_ENV:", process.env.NODE_ENV);
console.log("- CODESPACE_NAME:", process.env.CODESPACE_NAME);
console.log("- PORT:", process.env.PORT);
console.log("- HTTPS:", process.env.HTTPS);
console.log("- GOOGLE_CALLBACK_URL:", process.env.GOOGLE_CALLBACK_URL);
console.log("- isVercelProduction:", isVercelProduction);
console.log("- isDevTunnel:", isDevTunnel);
console.log("- Base URL:", baseURL);
console.log("- Google OAuth Callback URL:", googleCallbackURL);

// GitHub callback URL (follows same pattern as Google)
let githubCallbackURL;
if (process.env.GITHUB_CALLBACK_URL) {
  githubCallbackURL = process.env.GITHUB_CALLBACK_URL;
} else if (isVercelProduction) {
  githubCallbackURL = "https://code-collab-beta-v3.vercel.app/auth/github/callback";
} else {
  const protocol = process.env.HTTPS === 'true' ? 'https' : 'http';
  githubCallbackURL = `${protocol}://localhost:3002/auth/github/callback`;
}
console.log("- GitHub OAuth Callback URL:", githubCallbackURL);

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

// GitHub OAuth Strategy
passport.use(
  "github",
  new GitHubStrategy(
    {
      clientID: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
      callbackURL: githubCallbackURL,
      passReqToCallback: true,
      proxy: true, // Important for working with proxied connections
    },
    async (req, accessToken, refreshToken, profile, cb) => {
      try {
        console.log("GitHub profile:", profile.id, profile.displayName || profile.username);
        console.log("Looking up GitHub user with ID:", profile.id);

        if (!profile.id) {
          console.error("Invalid GitHub profile data - no ID");
          return cb(new Error("Invalid GitHub profile data"), null);
        }

        // GitHub emails might be null if user hasn't made their email public
        const email = profile.emails && profile.emails[0] ? profile.emails[0].value : null;
        const username = profile.username;

        // Use safe database operation to find user by GitHub ID
        let user = await safeDBOperation(async () => {
          return await collection.findOne({ githubId: profile.id });
        });

        // Create user object with necessary profile data
        const userData = {
          githubId: profile.id,
          fullname: profile.displayName || profile.username,
          username: username,
          picture: profile.photos?.[0]?.value,
          email: email,
          accessToken: accessToken,
          authType: "github", // Set auth type to github
          lastLogin: new Date(),
        };

        if (user) {
          // Update existing user with latest GitHub data and login time
          console.log("Updating existing GitHub user");
          user = await safeDBOperation(async () => {
            return await collection.findOneAndUpdate(
              { githubId: profile.id },
              { 
                $set: {
                  ...userData,
                  premium: user.premium || false, // Preserve premium status
                  subscriptionType: user.subscriptionType || 'free',
                  subscriptionEndDate: user.subscriptionEndDate,
                  paymentHistory: user.paymentHistory || []
                }
              },
              { returnDocument: "after" }
            );
          });
        } else {
          // Check if user exists with same email (if email is available)
          let existingUser = null;
          if (email) {
            existingUser = await safeDBOperation(async () => {
              return await collection.findOne({ email: email });
            });
          }

          if (existingUser) {
            // Link GitHub to existing account
            console.log("Linking GitHub to existing account");
            user = await safeDBOperation(async () => {
              return await collection.findOneAndUpdate(
                { email: email },
                { 
                  $set: {
                    githubId: profile.id,
                    username: username,
                    lastLogin: new Date(),
                    // Keep existing premium status and other data
                    premium: existingUser.premium || false,
                    subscriptionType: existingUser.subscriptionType || 'free',
                    subscriptionEndDate: existingUser.subscriptionEndDate,
                    paymentHistory: existingUser.paymentHistory || []
                  }
                },
                { returnDocument: "after" }
              );
            });
          } else {
            // Create new GitHub user
            console.log("Creating new GitHub user");
            userData.premium = false;
            userData.subscriptionType = 'free';
            userData.paymentHistory = [];
            
            user = await safeDBOperation(async () => {
              const result = await collection.insertOne(userData);
              return { ...userData, _id: result.insertedId };
            });
          }
        }

        if (!user) {
          console.error("Failed to create or find GitHub user");
          return cb(new Error("Failed to authenticate with GitHub"), null);
        }

        console.log("GitHub authentication successful for user:", user.email || user.username);
        return cb(null, user);
      } catch (error) {
        console.error("GitHub authentication error:", error);
        return cb(error, null);
      }
    }
  )
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

app.get("/dashboard", async (req, res) => {
  console.log("Dashboard route accessed");
  console.log("Session ID:", req.sessionID);
  console.log("Is authenticated:", req.isAuthenticated());
  console.log("User in session:", req.user);
  console.log("Environment:", process.env.NODE_ENV);

  try {
    // Check if user is authenticated
    if (req.isAuthenticated() && req.user) {
      // Update user activity - track login
      await safeDBOperation(async () => {
        await collection.updateOne(
          { email: req.user.email },
          { 
            $set: { 
              "activity.lastLogin": new Date()
            },
            $inc: {
              "activity.totalLogins": 1
            }
          }
        );
      });

      // Track login activity and start coding session
      await trackUserActivity(req.user.email, 'login', 'Signed in to CodeCollab', `Login from dashboard`);
      await startCodingSession(req.user.email);

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

// Profile route
app.get("/profile", async (req, res) => {
  console.log("Profile route accessed");
  console.log("Session ID:", req.sessionID);
  console.log("Is authenticated:", req.isAuthenticated());
  console.log("User in session:", req.user);

  try {
    // Check if user is authenticated
    if (req.isAuthenticated() && req.user) {
      // Get user stats from database
      const userStats = await safeDBOperation(async () => {
        // Get user data with stats
        const userData = await collection.findOne({ 
          email: req.user.email 
        });

        // Get rooms created by user
        const roomsCreated = await Room.countDocuments({ 
          createdBy: req.user.email 
        });

        // Get real statistics from database
        const collaborations = userData?.activity?.roomsJoined || 0;
        const totalCodingHours = Math.floor((userData?.activity?.totalCodingTimeMinutes || 0) / 60);
        const totalCodingMinutes = (userData?.activity?.totalCodingTimeMinutes || 0) % 60;
        const linesOfCode = userData?.activity?.totalLinesOfCode || 0;

        return {
          roomsCreated,
          collaborations,
          totalCodingHours,
          totalCodingMinutes,
          linesOfCode,
          lastLogin: userData?.activity?.lastLogin,
          totalLogins: userData?.activity?.totalLogins || 0,
          codeExecutions: userData?.activity?.codeExecutions || 0,
          aiRequestsTotal: userData?.activity?.aiRequestsTotal || 0,
          recentActivities: userData?.activity?.recentActivities || [],
          recentCodeSnippets: userData?.activity?.recentCodeSnippets || []
        };
      });

      return res.render("profile.ejs", {
        title: "Profile",
        user: req.user,
        stats: userStats
      });
    } else {
      console.log("User not authenticated, redirecting to signin");
      return res.redirect("/auth/signin?error=authentication_required");
    }
  } catch (error) {
    console.error("Profile route error:", error);
    console.error("Profile route error stack:", error.stack);
    return res.status(500).render("signin.ejs", {
      title: "Sign In",
      error: "An error occurred accessing your profile. Please sign in again.",
    });
  }
});

// Profile API endpoints
// Update user preferences
app.post("/api/profile/preferences", async (req, res) => {
  if (!req.isAuthenticated() || !req.user) {
    return res.status(401).json({ error: "Not authenticated" });
  }

  try {
    const { notifications, theme, defaultLanguage } = req.body;
    
    await safeDBOperation(async () => {
      await collection.updateOne(
        { email: req.user.email },
        { 
          $set: { 
            "preferences.notifications": notifications,
            "preferences.theme": theme,
            "preferences.defaultLanguage": defaultLanguage
          } 
        }
      );
    });

    res.json({ success: true, message: "Preferences updated successfully" });
  } catch (error) {
    console.error("Error updating preferences:", error);
    res.status(500).json({ error: "Failed to update preferences" });
  }
});

// Update user profile
app.post("/api/profile/update", async (req, res) => {
  if (!req.isAuthenticated() || !req.user) {
    return res.status(401).json({ error: "Not authenticated" });
  }

  try {
    const { fullname, picture } = req.body;
    
    await safeDBOperation(async () => {
      await collection.updateOne(
        { email: req.user.email },
        { 
          $set: { 
            fullname: fullname,
            picture: picture
          } 
        }
      );
    });

    // Update session user data
    req.user.fullname = fullname;
    req.user.picture = picture;

    res.json({ success: true, message: "Profile updated successfully" });
  } catch (error) {
    console.error("Error updating profile:", error);
    res.status(500).json({ error: "Failed to update profile" });
  }
});

// Get user activity
app.get("/api/profile/activity", async (req, res) => {
  if (!req.isAuthenticated() || !req.user) {
    return res.status(401).json({ error: "Not authenticated" });
  }

  try {
    const activities = await safeDBOperation(async () => {
      const userData = await collection.findOne({ 
        email: req.user.email 
      });

      const recentActivities = userData?.activity?.recentActivities || [];
      
      // Format activities for display
      const formattedActivities = recentActivities
        .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
        .slice(0, 10)
        .map(activity => {
          const timeAgo = getTimeAgo(activity.timestamp);
          return {
            type: activity.type,
            title: activity.title,
            time: timeAgo,
            icon: getIconForActivityType(activity.type),
            description: activity.description,
            metadata: activity.metadata
          };
        });

      return formattedActivities;
    });

    res.json({ success: true, activities });
  } catch (error) {
    console.error("Error fetching activity:", error);
    res.status(500).json({ error: "Failed to fetch activity" });
  }
});

// Export user data
app.get("/api/profile/export", async (req, res) => {
  if (!req.isAuthenticated() || !req.user) {
    return res.status(401).json({ error: "Not authenticated" });
  }

  try {
    const userData = await safeDBOperation(async () => {
      const user = await collection.findOne({ email: req.user.email });
      const userRooms = await Room.find({ createdBy: req.user.email });

      return {
        profile: {
          fullname: user?.fullname,
          email: user?.email,
          authType: user?.authType,
          createdAt: user?.createdAt,
          lastLogin: user?.activity?.lastLogin,
          totalLogins: user?.activity?.totalLogins
        },
        activity: user?.activity,
        preferences: user?.preferences,
        rooms: userRooms.map(room => ({
          roomId: room.roomId,
          roomName: room.roomName,
          createdAt: room.createdAt,
          isActive: room.isActive
        }))
      };
    });

    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', 'attachment; filename=codecollab-profile-data.json');
    res.json(userData);
  } catch (error) {
    console.error("Error exporting data:", error);
    res.status(500).json({ error: "Failed to export data" });
  }
});

// Delete user account
app.delete("/api/profile/delete", async (req, res) => {
  if (!req.isAuthenticated() || !req.user) {
    return res.status(401).json({ error: "Not authenticated" });
  }

  try {
    await safeDBOperation(async () => {
      // Delete user's rooms
      await Room.deleteMany({ createdBy: req.user.email });
      
      // Delete user account
      await collection.deleteOne({ email: req.user.email });
    });

    // Logout user
    req.logout((err) => {
      if (err) {
        console.error("Error logging out:", err);
      }
      req.session.destroy((err) => {
        if (err) {
          console.error("Error destroying session:", err);
        }
        res.json({ success: true, message: "Account deleted successfully" });
      });
    });
  } catch (error) {
    console.error("Error deleting account:", error);
    res.status(500).json({ error: "Failed to delete account" });
  }
});

// Reset user account (keep account but reset data)
app.post("/api/profile/reset", async (req, res) => {
  if (!req.isAuthenticated() || !req.user) {
    return res.status(401).json({ error: "Not authenticated" });
  }

  try {
    await safeDBOperation(async () => {
      // Delete user's rooms
      await Room.deleteMany({ createdBy: req.user.email });
      
      // Reset user activity data
      await collection.updateOne(
        { email: req.user.email },
        { 
          $set: { 
            "activity.roomsJoined": 0,
            "activity.codeExecutions": 0,
            "activity.aiRequestsTotal": 0
          } 
        }
      );
    });

    res.json({ success: true, message: "Account reset successfully" });
  } catch (error) {
    console.error("Error resetting account:", error);
    res.status(500).json({ error: "Failed to reset account" });
  }
});

// Refresh profile statistics
app.get("/api/profile/refresh-stats", async (req, res) => {
  if (!req.isAuthenticated() || !req.user) {
    return res.status(401).json({ error: "Not authenticated" });
  }

  try {
    const userStats = await safeDBOperation(async () => {
      const userData = await collection.findOne({ 
        email: req.user.email 
      });

      const roomsCreated = await Room.countDocuments({ 
        createdBy: req.user.email 
      });

      const collaborations = userData?.activity?.roomsJoined || 0;
      const totalCodingHours = Math.floor((userData?.activity?.totalCodingTimeMinutes || 0) / 60);
      const totalCodingMinutes = (userData?.activity?.totalCodingTimeMinutes || 0) % 60;
      const linesOfCode = userData?.activity?.totalLinesOfCode || 0;
      const codeExecutions = userData?.activity?.codeExecutions || 0;

      return {
        roomsCreated,
        collaborations,
        totalCodingHours,
        totalCodingMinutes,
        linesOfCode,
        codeExecutions
      };
    });

    res.json({ success: true, stats: userStats });
  } catch (error) {
    console.error("Error refreshing stats:", error);
    res.status(500).json({ error: "Failed to refresh statistics" });
  }
});

// Helper functions for activity formatting
function getTimeAgo(timestamp) {
  const now = new Date();
  const time = new Date(timestamp);
  const diffInSeconds = Math.floor((now - time) / 1000);
  
  if (diffInSeconds < 60) {
    return 'Just now';
  } else if (diffInSeconds < 3600) {
    const minutes = Math.floor(diffInSeconds / 60);
    return `${minutes} minute${minutes > 1 ? 's' : ''} ago`;
  } else if (diffInSeconds < 86400) {
    const hours = Math.floor(diffInSeconds / 3600);
    return `${hours} hour${hours > 1 ? 's' : ''} ago`;
  } else if (diffInSeconds < 604800) {
    const days = Math.floor(diffInSeconds / 86400);
    return `${days} day${days > 1 ? 's' : ''} ago`;
  } else {
    return time.toLocaleDateString();
  }
}

function getIconForActivityType(activityType) {
  const icons = {
    'login': 'person-check',
    'room_created': 'plus-circle',
    'room_joined': 'people',
    'code_executed': 'play-circle',
    'ai_request': 'robot',
    'file_saved': 'save',
    'collaboration': 'people-fill'
  };
  return icons[activityType] || 'activity';
}

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

    // Check user subscription to set room capacity
    let maxUsers = 4; // Default for free users
    try {
      const user = await safeDBOperation(async () => {
        return await collection.findOne({
          $or: [
            { email: req.user.email },
            { googleId: req.user.googleId },
            { _id: req.user._id }
          ]
        });
      });

      const subscription = user?.subscription || { isPro: false };
      
      // Check if subscription has expired
      if (subscription.isPro && subscription.subscriptionEnd && new Date() > new Date(subscription.subscriptionEnd)) {
        subscription.isPro = false;
      }

      maxUsers = subscription.isPro ? 50 : 4; // Pro users get 50, free users get 4
    } catch (error) {
      console.error("Error checking subscription for room creation:", error);
      // Default to free plan on error
    }

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
      maxUsers: maxUsers,
      lastAccessed: new Date()
    };

    // Save room to MongoDB
    await safeDBOperation(async () => {
      const room = new Room(roomData);
      await room.save();
    });

    // Track room creation activity
    await trackUserActivity(
      req.user.email, 
      'room_created', 
      `Created room: ${roomName}`,
      `${roomVisibility} room with ${roomLanguage} language`,
      { roomId, roomName, language: roomLanguage, visibility: roomVisibility }
    );

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

app.get("/room/:roomId", async (req, res) => {
  console.log("Room route accessed, user in session:", req.user);
  // Check if user is in session
  if (req.user) {
    const roomId = req.params.roomId;

    try {
      // Load room data from database
      const roomData = await safeDBOperation(async () => {
        const room = await Room.findOne({ roomId: roomId });
        return room;
      });

      // Load saved code and files
      const savedRoomData = await loadRoomCode(roomId);

      // Create room response data
      const roomResponse = {
        name: roomData?.name || req.session.roomName || "Coding Room " + roomId,
        language: savedRoomData.language || req.session.roomLanguage || "javascript",
        id: roomId,
        description: roomData?.description || req.session.roomDescription || "A collaborative coding room",
        visibility: req.session.roomVisibility || "public",
        isPasswordProtected: roomData?.hasPassword || req.session.isPasswordProtected || false,
        createdAt: roomData?.createdAt || new Date(),
        createdBy: roomData?.createdBy || req.user.email || req.user._id || req.user.id || req.user.googleId,
        currentCode: savedRoomData.code || '',
        savedFiles: savedRoomData.files || [],
        files: savedRoomData.files.length > 0 ? 
          savedRoomData.files.map(file => ({
            name: file.name,
            type: file.language,
            content: file.content,
            language: file.language
          })) : 
          [
            { name: "index.js", type: "js", content: savedRoomData.code || "// JavaScript code here", language: "javascript" },
            { name: "index.html", type: "html", content: "<!-- HTML code here -->", language: "html" },
            { name: "styles.css", type: "css", content: "/* CSS code here */", language: "css" },
          ],
      };

      // Clear session variables after use
      delete req.session.roomName;
      delete req.session.roomLanguage;
      delete req.session.roomDescription;
      delete req.session.roomVisibility;

      res.render("room.ejs", {
        title: roomResponse.name + " | CodeCollab",
        roomData: roomResponse,
        req, // Pass the request object to access user details in the template
      });

    } catch (error) {
      console.error("Error loading room:", error);
      
      // Fallback to default room data
      const fallbackRoomData = {
        name: req.session.roomName || "Coding Room " + roomId,
        language: req.session.roomLanguage || "javascript",
        id: roomId,
        description: req.session.roomDescription || "A collaborative coding room",
        visibility: req.session.roomVisibility || "public",
        isPasswordProtected: req.session.isPasswordProtected || false,
        createdAt: new Date(),
        createdBy: req.user.email || req.user._id || req.user.id || req.user.googleId,
        currentCode: '',
        files: [
          { name: "index.js", type: "js", content: "// JavaScript code here", language: "javascript" },
          { name: "index.html", type: "html", content: "<!-- HTML code here -->", language: "html" },
          { name: "styles.css", type: "css", content: "/* CSS code here */", language: "css" },
        ],
      };

      res.render("room.ejs", {
        title: fallbackRoomData.name + " | CodeCollab",
        roomData: fallbackRoomData,
        req,
      });
    }
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
app.post("/auth/forgot-password", async (req, res) => {
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

  try {
    await ensureDBConnection();
    
    // Find user by email
    const user = await collection.findOne({ email: email.toLowerCase() });
    
    // For security, we show the same message whether user exists or not
    if (!user) {
      return res.render("forgot-password.ejs", {
        title: "Forgot Password",
        success: "If an account with that email exists, we've sent a password reset link.",
      });
    }

    // Only allow password reset for local auth users
    if (user.authType !== 'local') {
      return res.render("forgot-password.ejs", {
        title: "Forgot Password",
        error: "Password reset is only available for accounts created with email/password. Please sign in using your social account.",
        formData: { email: email },
      });
    }

    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const tokenExpiry = new Date(Date.now() + 3600000); // 1 hour from now

    // Save token to database
    await collection.updateOne(
      { email: email.toLowerCase() },
      {
        $set: {
          'passwordReset.token': resetToken,
          'passwordReset.tokenExpiry': tokenExpiry
        }
      }
    );

    // Prepare reset URL - use production domain or fallback to request host
    const baseUrl = process.env.NODE_ENV === 'production' 
      ? 'https://www.code-collab.me' 
      : `${req.protocol}://${req.get('host')}`;
    const resetUrl = `${baseUrl}/auth/reset-password?token=${resetToken}`;

    // Email content
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'CodeCollab - Password Reset Request',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <div style="text-align: center; margin-bottom: 30px;">
            <h1 style="color: #3b82f6;">CodeCollab</h1>
          </div>
          
          <h2 style="color: #333;">Password Reset Request</h2>
          
          <p style="color: #555; font-size: 16px;">
            Hello ${user.fullname || 'User'},
          </p>
          
          <p style="color: #555; font-size: 16px;">
            We received a request to reset your password for your CodeCollab account. 
            Click the button below to reset your password:
          </p>
          
          <div style="text-align: center; margin: 30px 0;">
            <a href="${resetUrl}" 
               style="background-color: #3b82f6; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block; font-weight: 500;">
              Reset Password
            </a>
          </div>
          
          <p style="color: #555; font-size: 14px;">
            If the button doesn't work, copy and paste this link into your browser:
          </p>
          <p style="color: #3b82f6; font-size: 14px; word-break: break-all;">
            ${resetUrl}
          </p>
          
          <p style="color: #777; font-size: 14px; margin-top: 30px;">
            This link will expire in 1 hour for security reasons.
          </p>
          
          <p style="color: #777; font-size: 14px;">
            If you didn't request this password reset, please ignore this email. 
            Your password will remain unchanged.
          </p>
          
          <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
          <p style="color: #999; font-size: 12px; text-align: center;">
            CodeCollab - Real-time collaborative coding platform
          </p>
        </div>
      `
    };

    // Check if email is configured
    if (!transporter) {
      return res.render("forgot-password.ejs", {
        title: "Forgot Password",
        error: "Email service is not configured. Please contact support for password reset assistance.",
        formData: { email: email },
      });
    }

    // Send email
    await transporter.sendMail(mailOptions);
    
    console.log(`Password reset email sent to: ${email}`);

    return res.render("forgot-password.ejs", {
      title: "Forgot Password",
      success: "Password reset link has been sent to your email address. Please check your inbox.",
    });

  } catch (error) {
    console.error("Error in forgot password:", error);
    return res.render("forgot-password.ejs", {
      title: "Forgot Password",
      error: "An error occurred while processing your request. Please try again later.",
      formData: { email: email },
    });
  }
});

// Password reset routes - handle the link from email
app.get("/auth/reset-password", async (req, res) => {
  console.log("=== GET /auth/reset-password called ===");
  const token = req.query.token;
  console.log("Token from URL:", token);

  if (!token) {
    console.log("No token provided in URL - redirecting to signin");
    return res.render("signin.ejs", {
      title: "Sign In",
      error: "Invalid password reset link. Please request a new password reset from the forgot password page.",
    });
  }

  try {
    await ensureDBConnection();
    
    // Find user with valid token
    const user = await collection.findOne({
      'passwordReset.token': token,
      'passwordReset.tokenExpiry': { $gt: new Date() } // Token not expired
    });

    console.log("User found for token:", user ? user.email : 'No user found');

    if (!user) {
      return res.render("signin.ejs", {
        title: "Sign In",
        error: "Password reset link is invalid or has expired. Please request a new one.",
      });
    }

    // Render reset password form
    console.log("Rendering reset-password.ejs with token:", token, "for user:", user.email);
    res.render("reset-password.ejs", {
      title: "Reset Password",
      token: token,
      email: user.email
    });

  } catch (error) {
    console.error("Error in reset password GET:", error);
    return res.render("signin.ejs", {
      title: "Sign In",
      error: "An error occurred. Please try again later.",
    });
  }
});

app.post("/auth/reset-password", async (req, res) => {
  const { token, password, confirmPassword } = req.body;
  console.log("Reset password POST route accessed with token:", token);

  if (!token || !password || !confirmPassword) {
    console.log("Missing required fields");
    return res.render("reset-password.ejs", {
      title: "Reset Password",
      error: "All fields are required.",
      token: token
    });
  }

  if (password !== confirmPassword) {
    console.log("Passwords don't match");
    return res.render("reset-password.ejs", {
      title: "Reset Password",
      error: "Passwords do not match.",
      token: token
    });
  }

  if (password.length < 6) {
    console.log("Password too short");
    return res.render("reset-password.ejs", {
      title: "Reset Password",
      error: "Password must be at least 6 characters long.",
      token: token
    });
  }

  try {
    await ensureDBConnection();
    
    // Find user with valid token
    const user = await collection.findOne({
      'passwordReset.token': token,
      'passwordReset.tokenExpiry': { $gt: new Date() }
    });

    if (!user) {
      console.log("Invalid or expired token");
      return res.render("signin.ejs", {
        title: "Sign In",
        error: "Password reset link is invalid or has expired.",
      });
    }

    console.log("User found, updating password for:", user.email);

    // Save password as plain text (no hashing)
    const newPassword = password;

    // Update user's password and remove reset token
    await collection.updateOne(
      { _id: user._id },
      {
        $set: {
          password: newPassword
        },
        $unset: {
          'passwordReset.token': '',
          'passwordReset.tokenExpiry': ''
        }
      }
    );

    console.log(`Password reset successfully for user: ${user.email}`);

    return res.render("signin.ejs", {
      title: "Sign In",
      success: "Your password has been reset successfully. Please sign in with your new password.",
    });

  } catch (error) {
    console.error("Error in reset password POST:", error);
    return res.render("reset-password.ejs", {
      title: "Reset Password",
      error: "An error occurred while resetting your password. Please try again.",
      token: token
    });
  }
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

    // Create the full redirect URL using the correct base URL
    const redirectURL = returnTo.startsWith('http') ? returnTo : `${baseURL}${returnTo}`;
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
    // Store error message in session
    req.session.authError = err.message || "Google authentication failed";
    // Log specific error details for debugging
    if (err.oauthError) {
      console.error("OAuth error details:", err.oauthError);
    }
    res.redirect(
      "/auth/signin?error=google_auth_failed&message=" +
        encodeURIComponent(err.message || "Authentication failed"),
    );
  },
);

// GitHub OAuth routes with improved logging
app.get(
  "/auth/github",
  (req, res, next) => {
    console.log("Starting GitHub OAuth process");
    // Store the return URL in session if provided
    if (req.query.returnTo) {
      req.session.returnTo = req.query.returnTo;
    }
    next();
  },
  passport.authenticate("github", {
    scope: ["user:email", "read:user"],
  }),
);

app.get(
  "/auth/github/callback",
  (req, res, next) => {
    console.log("Received GitHub OAuth callback", req.query);
    next();
  },
  passport.authenticate("github", {
    failureRedirect: "/auth/signin",
    failWithError: true,
  }),
  function (req, res) {
    console.log("GitHub auth successful, redirecting to dashboard");
    console.log("User authenticated:", req.user?.email || req.user?.username);
    console.log("Session ID after GitHub auth:", req.sessionID);

    // Store auth type and timestamp in session
    req.session.authType = "github";
    req.session.authTime = new Date().toISOString();
    req.session.loginSuccess = true;

    // Get the return URL from session or default to dashboard
    const returnTo = req.session.returnTo || "/dashboard";
    delete req.session.returnTo;

    // Create the full redirect URL using the correct base URL
    const redirectURL = returnTo.startsWith('http') ? returnTo : `${baseURL}${returnTo}`;
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
    console.error("GitHub auth error:", err);
    // Store error message in session
    req.session.authError = err.message || "GitHub authentication failed";
    // Log specific error details for debugging
    if (err.oauthError) {
      console.error("OAuth error details:", err.oauthError);
    }
    res.redirect(
      "/auth/signin?error=github_auth_failed&message=" +
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

// Policy Pages Routes (Required for Razorpay compliance)
app.get("/contact", (req, res) => {
  res.render("contact.ejs", { title: "Contact Us | CodeCollab" });
});

app.get("/terms", (req, res) => {
  res.render("terms.ejs", { title: "Terms and Conditions | CodeCollab" });
});

app.get("/privacy", (req, res) => {
  res.render("privacy.ejs", { title: "Privacy Policy | CodeCollab" });
});

app.get("/refund", (req, res) => {
  res.render("refund.ejs", { title: "Cancellation and Refund Policy | CodeCollab" });
});

app.get("/shipping", (req, res) => {
  res.render("shipping.ejs", { title: "Shipping & Delivery Policy | CodeCollab" });
});

// Payment Routes
app.get("/payment", (req, res) => {
  // Check if user is authenticated
  if (!req.user) {
    return res.redirect("/auth/signin?error=authentication_required");
  }

  // Check if user is already pro
  if (req.user.subscription && req.user.subscription.isPro) {
    return res.redirect("/dashboard?message=You are already a Pro member!");
  }

  res.render("payment.ejs", {
    title: "Upgrade to CodeCollab Pro",
    user: req.user,
    razorpayKeyId: process.env.RAZORPAY_KEY_ID,
    error: req.query.error || null,
    success: req.query.success || null
  });
});

// Create payment order
app.post("/api/payment/create-order", async (req, res) => {
  try {
    // Check if user is authenticated
    if (!req.user) {
      return res.status(401).json({ 
        success: false, 
        message: "User not authenticated" 
      });
    }

    // Check if user is already pro
    if (req.user.subscription && req.user.subscription.isPro) {
      return res.status(400).json({ 
        success: false, 
        message: "User is already a Pro member" 
      });
    }

    const { amount, currency } = req.body;

    // Validate amount (₹99 = 9900 paise)
    if (amount !== 9900) {
      return res.status(400).json({ 
        success: false, 
        message: "Invalid amount" 
      });
    }

    // Create Razorpay order
    const orderOptions = {
      amount: amount, // Amount in paise
      currency: currency || 'INR',
      receipt: `cc_${Date.now()}`,
      notes: {
        user_email: req.user.email,
        subscription_type: 'pro_quarterly',
        user_id: req.user._id?.toString() || req.user.googleId
      }
    };

    const order = await razorpay.orders.create(orderOptions);
    
    console.log("Created Razorpay order:", order.id);

    res.json({
      success: true,
      order: {
        id: order.id,
        amount: order.amount,
        currency: order.currency
      }
    });

  } catch (error) {
    console.error("Payment order creation error:", error);
    const errorMessage = error?.error?.description || error?.message || JSON.stringify(error) || "Unknown error";
    res.status(500).json({ 
      success: false, 
      message: "Failed to create payment order: " + errorMessage
    });
  }
});

// Verify payment
app.post("/api/payment/verify", async (req, res) => {
  try {
    // Check if user is authenticated
    if (!req.user) {
      return res.status(401).json({ 
        success: false, 
        message: "User not authenticated" 
      });
    }

    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;

    // Verify payment signature
    const crypto = await import('crypto');
    const expectedSignature = crypto.default
      .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
      .update(`${razorpay_order_id}|${razorpay_payment_id}`)
      .digest('hex');

    if (expectedSignature !== razorpay_signature) {
      return res.status(400).json({ 
        success: false, 
        message: "Invalid payment signature" 
      });
    }

    // Fetch payment details from Razorpay
    const payment = await razorpay.payments.fetch(razorpay_payment_id);
    
    if (payment.status !== 'captured') {
      return res.status(400).json({ 
        success: false, 
        message: "Payment not captured" 
      });
    }

    // Update user subscription in database
    const subscriptionEnd = new Date();
    subscriptionEnd.setMonth(subscriptionEnd.getMonth() + 3); // Add 3 months

    const updateResult = await safeDBOperation(async () => {
      return await collection.updateOne(
        { 
          $or: [
            { email: req.user.email },
            { googleId: req.user.googleId },
            { _id: req.user._id }
          ]
        },
        {
          $set: {
            'subscription.isPro': true,
            'subscription.planType': 'pro',
            'subscription.subscriptionStart': new Date(),
            'subscription.subscriptionEnd': subscriptionEnd,
            'subscription.autoRenew': true,
            'subscription.paymentId': razorpay_payment_id,
            // Enable all Pro features
            'subscription.features.aiChatEnabled': true,
            'subscription.features.aiCodeAnalysisEnabled': true,
            'subscription.features.unlimitedRooms': true,
            'subscription.features.prioritySupport': true,
            'subscription.features.advancedCollaboration': true,
            // Update limits for Pro users
            'subscription.limits.maxRoomCapacity': 50,
            'subscription.limits.aiRequestsPerDay': 1000
          },
          $push: {
            'subscription.paymentHistory': {
              paymentId: razorpay_payment_id,
              orderId: razorpay_order_id,
              amount: payment.amount,
              currency: payment.currency,
              status: payment.status,
              createdAt: new Date()
            }
          }
        }
      );
    });

    if (updateResult.modifiedCount === 0) {
      console.error("Failed to update user subscription");
      return res.status(500).json({ 
        success: false, 
        message: "Failed to update subscription" 
      });
    }

    console.log(`User ${req.user.email} upgraded to Pro successfully`);

    res.json({
      success: true,
      message: "Payment verified and subscription activated successfully"
    });

  } catch (error) {
    console.error("Payment verification error:", error);
    res.status(500).json({ 
      success: false, 
      message: "Payment verification failed: " + error.message 
    });
  }
});

// Razorpay Webhook Handler - for reliable payment status updates
app.post("/api/payment/webhook", express.raw({ type: 'application/json' }), async (req, res) => {
  try {
    const webhookSecret = process.env.RAZORPAY_WEBHOOK_SECRET;
    
    // If webhook secret is not configured, skip signature verification (not recommended for production)
    if (webhookSecret) {
      const shasum = crypto.createHmac('sha256', webhookSecret);
      shasum.update(JSON.stringify(req.body));
      const digest = shasum.digest('hex');
      
      if (digest !== req.headers['x-razorpay-signature']) {
        console.error('Webhook signature verification failed');
        return res.status(400).json({ success: false, message: 'Invalid signature' });
      }
    }

    const event = req.body;
    console.log('Razorpay webhook event:', event.event);

    switch (event.event) {
      case 'payment.captured':
        const payment = event.payload.payment.entity;
        console.log(`Payment captured: ${payment.id}, Amount: ${payment.amount}`);
        
        // Extract user email from payment notes
        const userEmail = payment.notes?.user_email;
        if (userEmail) {
          const subscriptionEnd = new Date();
          subscriptionEnd.setMonth(subscriptionEnd.getMonth() + 3); // Add 3 months
          
          await safeDBOperation(async () => {
            return await collection.updateOne(
              { email: userEmail },
              {
                $set: {
                  'subscription.isPro': true,
                  'subscription.planType': 'pro',
                  'subscription.subscriptionStart': new Date(),
                  'subscription.subscriptionEnd': subscriptionEnd,
                  'subscription.paymentId': payment.id,
                  'subscription.features.aiChatEnabled': true,
                  'subscription.features.aiCodeAnalysisEnabled': true,
                  'subscription.features.unlimitedRooms': true,
                  'subscription.features.prioritySupport': true,
                  'subscription.limits.maxRoomCapacity': 50,
                  'subscription.limits.aiRequestsPerDay': 1000
                }
              }
            );
          });
          console.log(`Subscription activated via webhook for ${userEmail}`);
        }
        break;

      case 'payment.failed':
        const failedPayment = event.payload.payment.entity;
        console.log(`Payment failed: ${failedPayment.id}, Reason: ${failedPayment.error_description}`);
        break;

      case 'order.paid':
        const order = event.payload.order.entity;
        console.log(`Order paid: ${order.id}`);
        break;

      default:
        console.log(`Unhandled webhook event: ${event.event}`);
    }

    res.json({ success: true, received: true });
  } catch (error) {
    console.error('Webhook processing error:', error);
    res.status(500).json({ success: false, message: 'Webhook processing failed' });
  }
});

// Get Pro features list
app.get("/api/pro-features", (req, res) => {
  const proFeatures = {
    unlimitedRooms: {
      name: "Unlimited Room Capacity",
      description: "Create rooms with up to 50 users instead of 4",
      capacity: req.user?.subscription?.isPro ? "50 users" : "4 users"
    },
    prioritySupport: {
      name: "Priority Support",
      description: "Get priority customer support and faster response times",
      available: req.user?.subscription?.isPro || false
    },
    advancedCollaboration: {
      name: "Advanced Collaboration",
      description: "Enhanced real-time collaboration features and tools",
      available: req.user?.subscription?.isPro || false
    },
    higherAiLimits: {
      name: "Higher AI Usage Limits",
      description: "Get 1000 AI requests per day instead of 10",
      limit: req.user?.subscription?.isPro ? "1000 requests/day" : "10 requests/day"
    }
  };

  const freeFeatures = {
    basicCollaboration: {
      name: "Basic Collaboration",
      description: "Real-time code editing with up to 4 users",
      included: true
    },
    codeExecution: {
      name: "Code Execution",
      description: "Run code in multiple programming languages",
      included: true
    },
    roomCreation: {
      name: "Room Creation", 
      description: "Create and manage coding rooms",
      included: true
    },
    aiChatAssistant: {
      name: "AI Chat Assistant",
      description: "Get intelligent coding help with AI-powered conversations (10 requests/day)",
      included: true,
      limit: "10 requests/day"
    },
    aiCodeAnalysis: {
      name: "AI Code Analysis", 
      description: "Analyze your code for bugs, optimizations, and explanations (10 requests/day)",
      included: true,
      limit: "10 requests/day"
    }
  };

  res.json({
    success: true,
    user: {
      isPro: req.user?.subscription?.isPro || false,
      email: req.user?.email,
      planType: req.user?.subscription?.planType || 'free'
    },
    features: {
      free: freeFeatures,
      pro: proFeatures
    },
    pricing: {
      free: {
        price: "₹0/month",
        features: Object.keys(freeFeatures)
      },
      pro: {
        price: "₹99/3 months", 
        features: Object.keys(proFeatures),
        additionalBenefits: ["Higher AI usage limits (1000/day)", "Unlimited room capacity", "Priority support"]
      }
    }
  });
});

// Manual Pro upgrade endpoint (for admin testing)
app.post("/api/admin/upgrade-user", async (req, res) => {
  // Check if user is authenticated
  if (!req.user) {
    return res.status(401).json({ 
      success: false, 
      message: "User not authenticated" 
    });
  }

  // For security, only allow in development mode or for specific admin users
  if (process.env.NODE_ENV === 'production') {
    // In production, only allow specific admin emails
    const adminEmails = (process.env.ADMIN_EMAILS || '').split(',');
    if (!adminEmails.includes(req.user.email)) {
      return res.status(403).json({
        success: false,
        message: "Access denied. Admin privileges required."
      });
    }
  }

  try {
    const { targetUserEmail } = req.body;
    
    // If no target email provided, upgrade the current user
    const userEmail = targetUserEmail || req.user.email;
    
    console.log(`Admin ${req.user.email} upgrading user ${userEmail} to Pro`);
    
    const success = await upgradeUserToPro(userEmail, {
      paymentId: 'ADMIN_UPGRADE_' + Date.now(),
      orderId: 'ADMIN_ORDER_' + Date.now(),
      amount: 0,
      currency: 'INR',
      status: 'captured'
    });

    if (success) {
      res.json({
        success: true,
        message: `User ${userEmail} has been successfully upgraded to Pro`,
        upgradeType: 'admin_manual'
      });
    } else {
      res.status(500).json({
        success: false,
        message: "Failed to upgrade user to Pro"
      });
    }

  } catch (error) {
    console.error("Admin upgrade error:", error);
    res.status(500).json({ 
      success: false, 
      message: "Failed to upgrade user: " + error.message 
    });
  }
});

// Check subscription status
app.get("/api/subscription/status", async (req, res) => {
  try {
    // Check if user is authenticated
    if (!req.user) {
      return res.status(401).json({ 
        success: false, 
        message: "User not authenticated" 
      });
    }

    // Get fresh user data from database
    const user = await safeDBOperation(async () => {
      return await collection.findOne({
        $or: [
          { email: req.user.email },
          { googleId: req.user.googleId },
          { _id: req.user._id }
        ]
      });
    });

    if (!user) {
      return res.status(404).json({ 
        success: false, 
        message: "User not found" 
      });
    }

    const subscription = user.subscription || { isPro: false, planType: 'free' };
    
    // Check if subscription has expired
    if (subscription.isPro && subscription.subscriptionEnd && new Date() > new Date(subscription.subscriptionEnd)) {
      // Subscription expired, downgrade to free
      await safeDBOperation(async () => {
        return await collection.updateOne(
          { _id: user._id },
          {
            $set: {
              'subscription.isPro': false,
              'subscription.planType': 'free',
              'subscription.features.aiChatEnabled': false,
              'subscription.features.aiCodeAnalysisEnabled': false,
              'subscription.features.unlimitedRooms': false,
              'subscription.features.prioritySupport': false,
              'subscription.features.advancedCollaboration': false,
              'subscription.limits.maxRoomCapacity': 4
            }
          }
        );
      });
      subscription.isPro = false;
      subscription.planType = 'free';
    }

    // Return comprehensive subscription status
    res.json({
      success: true,
      subscription: {
        isPro: subscription.isPro || false,
        planType: subscription.planType || 'free',
        subscriptionStart: subscription.subscriptionStart,
        subscriptionEnd: subscription.subscriptionEnd,
        daysRemaining: subscription.subscriptionEnd ? 
          Math.max(0, Math.ceil((new Date(subscription.subscriptionEnd) - new Date()) / (1000 * 60 * 60 * 24))) : 0,
        features: {
          aiChatEnabled: subscription.features?.aiChatEnabled || false,
          aiCodeAnalysisEnabled: subscription.features?.aiCodeAnalysisEnabled || false,
          unlimitedRooms: subscription.features?.unlimitedRooms || false,
          prioritySupport: subscription.features?.prioritySupport || false,
          advancedCollaboration: subscription.features?.advancedCollaboration || false
        },
        limits: {
          maxRoomCapacity: subscription.limits?.maxRoomCapacity || 4,
          aiRequestsPerDay: subscription.limits?.aiRequestsPerDay || 10,
          dailyAiUsage: subscription.limits?.dailyAiUsage || { date: new Date(), count: 0 }
        }
      },
      user: {
        email: user.email,
        fullname: user.fullname,
        authType: user.authType
      }
    });

  } catch (error) {
    console.error("Subscription status error:", error);
    res.status(500).json({ 
      success: false, 
      message: "Failed to get subscription status: " + error.message 
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

// Initialize Gemini AI
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

// Middleware to check pro subscription
async function requireProSubscription(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ 
      error: "Unauthorized",
      requiresPro: true,
      message: "Please sign in to access this feature" 
    });
  }

  try {
    // Get fresh user data from database to check subscription
    const user = await safeDBOperation(async () => {
      return await collection.findOne({
        $or: [
          { email: req.user.email },
          { googleId: req.user.googleId },
          { _id: req.user._id }
        ]
      });
    });

    if (!user) {
      return res.status(404).json({ 
        error: "User not found",
        requiresPro: true 
      });
    }

    const subscription = user.subscription || { isPro: false };
    
    // Check if subscription has expired
    if (subscription.isPro && subscription.subscriptionEnd && new Date() > new Date(subscription.subscriptionEnd)) {
      // Subscription expired, downgrade to free
      await safeDBOperation(async () => {
        return await collection.updateOne(
          { _id: user._id },
          {
            $set: {
              'subscription.isPro': false,
              'subscription.planType': 'free',
              'subscription.features.aiChatEnabled': false,
              'subscription.features.aiCodeAnalysisEnabled': false,
              'subscription.features.unlimitedRooms': false,
              'subscription.features.prioritySupport': false,
              'subscription.features.advancedCollaboration': false,
              'subscription.limits.maxRoomCapacity': 4
            }
          }
        );
      });
      subscription.isPro = false;
    }

    if (!subscription.isPro) {
      return res.status(403).json({ 
        error: "This feature requires CodeCollab Pro subscription",
        requiresPro: true,
        message: "Upgrade to Pro to access AI-powered code analysis, debugging, and optimization features",
        upgradeUrl: "/payment",
        features: {
          available: ['Basic collaboration', 'Limited rooms (4 users)', 'Basic code execution', 'AI Chat Assistant (10/day)', 'AI Code Analysis (10/day)'],
          proFeatures: ['Unlimited room capacity (50 users)', 'Higher AI limits (1000/day)', 'Priority support', 'Advanced collaboration']
        }
      });
    }

    // Update req.user with fresh subscription data
    req.user.subscription = subscription;
    next();
  } catch (error) {
    console.error("Pro subscription check error:", error);
    return res.status(500).json({ 
      error: "Failed to verify subscription status",
      requiresPro: true 
    });
  }
}

// Middleware to check specific Pro feature access
function requireProFeature(featureName) {
  return async (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ 
        error: "Unauthorized",
        requiresPro: true,
        message: "Please sign in to access this feature" 
      });
    }

    try {
      // Get fresh user data from database
      const user = await safeDBOperation(async () => {
        return await collection.findOne({
          $or: [
            { email: req.user.email },
            { googleId: req.user.googleId },
            { _id: req.user._id }
          ]
        });
      });

      if (!user) {
        return res.status(404).json({ 
          error: "User not found",
          requiresPro: true 
        });
      }

      const subscription = user.subscription || { isPro: false };
      
      // Check if subscription has expired
      if (subscription.isPro && subscription.subscriptionEnd && new Date() > new Date(subscription.subscriptionEnd)) {
        subscription.isPro = false;
      }

      // Check if user has Pro subscription and specific feature enabled
      const hasFeature = subscription.isPro && 
                        subscription.features && 
                        subscription.features[featureName];

      if (!hasFeature) {
        const featureDisplayNames = {
          aiChatEnabled: 'AI Chat Assistant',
          aiCodeAnalysisEnabled: 'AI Code Analysis',
          unlimitedRooms: 'Unlimited Room Capacity',
          prioritySupport: 'Priority Support',
          advancedCollaboration: 'Advanced Collaboration Features'
        };

        return res.status(403).json({ 
          error: `This feature requires CodeCollab Pro: ${featureDisplayNames[featureName] || featureName}`,
          requiresPro: true,
          featureRequired: featureName,
          featureDisplayName: featureDisplayNames[featureName] || featureName,
          message: `Upgrade to Pro to access ${featureDisplayNames[featureName] || featureName}`,
          upgradeUrl: "/payment"
        });
      }

      // Update req.user with fresh subscription data
      req.user.subscription = subscription;
      next();
    } catch (error) {
      console.error(`Pro feature check error for ${featureName}:`, error);
      return res.status(500).json({ 
        error: "Failed to verify feature access",
        requiresPro: true 
      });
    }
  };
}

// Helper function to update user subscription to Pro
async function upgradeUserToPro(userId, paymentDetails = {}) {
  try {
    const subscriptionEnd = new Date();
    subscriptionEnd.setMonth(subscriptionEnd.getMonth() + 3); // Add 3 months

    const updateResult = await safeDBOperation(async () => {
      return await collection.updateOne(
        { 
          $or: [
            { email: userId },
            { googleId: userId },
            { _id: userId }
          ]
        },
        {
          $set: {
            'subscription.isPro': true,
            'subscription.planType': 'pro',
            'subscription.subscriptionStart': new Date(),
            'subscription.subscriptionEnd': subscriptionEnd,
            'subscription.autoRenew': true,
            'subscription.paymentId': paymentDetails.paymentId || null,
            // Enable all Pro features
            'subscription.features.aiChatEnabled': true,
            'subscription.features.aiCodeAnalysisEnabled': true,
            'subscription.features.unlimitedRooms': true,
            'subscription.features.prioritySupport': true,
            'subscription.features.advancedCollaboration': true,
            // Update limits
            'subscription.limits.maxRoomCapacity': 50,
            'subscription.limits.aiRequestsPerDay': 1000
          },
          $push: paymentDetails.paymentId ? {
            'subscription.paymentHistory': {
              paymentId: paymentDetails.paymentId,
              orderId: paymentDetails.orderId,
              amount: paymentDetails.amount,
              currency: paymentDetails.currency,
              status: paymentDetails.status,
              createdAt: new Date()
            }
          } : {}
        }
      );
    });

    return updateResult.modifiedCount > 0;
  } catch (error) {
    console.error("Error upgrading user to Pro:", error);
    return false;
  }
}

// Helper function to check daily AI usage limit
async function checkAiUsageLimit(userId) {
  try {
    const user = await safeDBOperation(async () => {
      // Check if userId looks like an ObjectId (24 char hex string)
      const isObjectId = /^[0-9a-fA-F]{24}$/.test(userId);
      
      if (isObjectId) {
        return await collection.findOne({ _id: userId });
      } else {
        return await collection.findOne({
          $or: [
            { email: userId },
            { googleId: userId }
          ]
        });
      }
    });

    if (!user) return { allowed: false, reason: 'User not found' };

    const subscription = user.subscription || { isPro: false };
    const today = new Date().toDateString();
    
    // Pro users have higher limits
    const dailyLimit = subscription.isPro ? 1000 : 5;
    
    // Check if daily usage tracking exists and is for today
    if (!subscription.limits || 
        !subscription.limits.dailyAiUsage || 
        new Date(subscription.limits.dailyAiUsage.date).toDateString() !== today) {
      // Reset daily usage for new day
      await safeDBOperation(async () => {
        return await collection.updateOne(
          { _id: user._id },
          {
            $set: {
              'subscription.limits.dailyAiUsage.date': new Date(),
              'subscription.limits.dailyAiUsage.count': 0
            }
          }
        );
      });
      return { allowed: true, remaining: dailyLimit };
    }

    const currentUsage = subscription.limits.dailyAiUsage.count || 0;
    
    if (currentUsage >= dailyLimit) {
      return { 
        allowed: false, 
        reason: subscription.isPro ? 'Daily Pro limit reached' : 'Daily limit reached. Upgrade to Pro for higher limits.',
        requiresPro: !subscription.isPro
      };
    }

    return { 
      allowed: true, 
      remaining: dailyLimit - currentUsage,
      isPro: subscription.isPro
    };
  } catch (error) {
    console.error("Error checking AI usage limit:", error);
    return { allowed: false, reason: 'Error checking usage limit' };
  }
}

// Helper function to increment AI usage
async function incrementAiUsage(userId) {
  try {
    const today = new Date();
    await safeDBOperation(async () => {
      return await collection.updateOne(
        {
          $or: [
            { email: userId },
            { googleId: userId },
            { _id: userId }
          ]
        },
        {
          $inc: {
            'subscription.limits.dailyAiUsage.count': 1,
            'activity.aiRequestsTotal': 1
          },
          $set: {
            'subscription.limits.dailyAiUsage.date': today
          }
        }
      );
    });
  } catch (error) {
    console.error("Error incrementing AI usage:", error);
  }
}

// Available AI models
const AI_MODELS = {
  'gemini-2.0-flash-exp': 'Gemini 2.0 Flash (Experimental)',
  'gemini-1.5-flash': 'Gemini 1.5 Flash',
  'gemini-1.5-pro': 'Gemini 1.5 Pro',
  'gemini-1.0-pro': 'Gemini 1.0 Pro'
};

// AI Chat endpoint - Available for all users
app.post("/api/ai-chat", async (req, res) => {
  try {
    // Check if user is authenticated
    if (!req.user) {
      return res.status(401).json({ 
        error: "Unauthorized",
        message: "Please sign in to access this feature" 
      });
    }

    // Check AI usage limit (different limits for Pro vs Free users)
    const usageCheck = await checkAiUsageLimit(req.user.email || req.user.googleId || req.user._id);
    if (!usageCheck.allowed) {
      return res.status(429).json({
        error: usageCheck.reason,
        requiresPro: usageCheck.requiresPro || false,
        upgradeUrl: "/payment"
      });
    }

    const { message, context, model = 'gemini-2.0-flash-exp', conversationHistory = [] } = req.body;

    if (!message) {
      return res.status(400).json({ error: "Message is required" });
    }

    const userPlan = req.user.subscription?.isPro ? 'Pro' : 'Free';
    console.log(`AI Chat request from ${req.user.email} (${userPlan} user) - Remaining: ${usageCheck.remaining}`);

    // Initialize the AI model
    const aiModel = genAI.getGenerativeModel({ model: model });

    // Create context for the AI
    let systemPrompt = `You are an AI coding assistant integrated into CodeCollab, a real-time collaborative coding platform. You help developers with:

1. Code explanations and debugging
2. Suggesting improvements and best practices
3. Writing code snippets and functions
4. Explaining programming concepts
5. Code reviews and optimization suggestions

Current context:
- User: ${req.user.fullname || req.user.email} (CodeCollab ${userPlan})
- Platform: CodeCollab Real-time Coding Environment
- User Plan: ${userPlan} ${userPlan === 'Pro' ? '(Advanced AI features enabled)' : '(Standard AI features)'}

Please provide helpful, accurate, and concise responses. Format code using markdown code blocks with appropriate language tags.`;

    if (context && context.code) {
      systemPrompt += `\n\nCurrent code in editor (${context.language || 'unknown'}):\n\`\`\`${context.language || ''}\n${context.code}\n\`\`\``;
    }

    if (context && context.selectedText) {
      systemPrompt += `\n\nSelected text: "${context.selectedText}"`;
    }

    // Build conversation history
    let chatHistory = [];
    
    // Add system prompt
    chatHistory.push({
      role: "user",
      parts: [{ text: systemPrompt }]
    });
    
    const welcomeMessage = userPlan === 'Pro' 
      ? "I'm your AI coding assistant! As a Pro user, you have access to advanced AI features with higher usage limits. I'm ready to help you with coding questions, debugging, code reviews, and programming guidance. What would you like help with?"
      : "I'm your AI coding assistant! I'm ready to help you with coding questions, debugging, code reviews, and programming guidance. What would you like help with?";
    
    chatHistory.push({
      role: "model", 
      parts: [{ text: welcomeMessage }]
    });

    // Add conversation history
    conversationHistory.forEach(msg => {
      if (msg.role === 'user' || msg.role === 'assistant') {
        chatHistory.push({
          role: msg.role === 'assistant' ? 'model' : 'user',
          parts: [{ text: msg.content }]
        });
      }
    });

    // Add current message
    chatHistory.push({
      role: "user",
      parts: [{ text: message }]
    });

    const chat = aiModel.startChat({
      history: chatHistory.slice(0, -1), // Don't include the current message in history
      generationConfig: {
        maxOutputTokens: 2048,
        temperature: 0.7,
        topP: 0.8,
        topK: 40,
      },
    });

    const result = await chat.sendMessage(message);
    const response = await result.response;
    const aiResponse = response.text();

    // Increment usage count
    await incrementAiUsage(req.user.email || req.user.googleId || req.user._id);

    res.json({
      response: aiResponse,
      model: model,
      timestamp: new Date().toISOString(),
      usage: {
        remaining: Math.max(0, usageCheck.remaining - 1),
        isPro: usageCheck.isPro,
        plan: userPlan
      }
    });

  } catch (error) {
    console.error("AI Chat error:", error);
    res.status(500).json({ 
      error: "Failed to get AI response",
      details: error.message 
    });
  }
});

// Get available AI models
app.get("/api/ai-models", (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  res.json({
    models: AI_MODELS,
    defaultModel: 'gemini-2.0-flash-exp'
  });
});

// AI Code Analysis endpoint - Available for all users
app.post("/api/ai-analyze", async (req, res) => {
  try {
    // Check if user is authenticated
    if (!req.user) {
      return res.status(401).json({ 
        error: "Unauthorized",
        message: "Please sign in to access this feature" 
      });
    }

    // Check AI usage limit
    const usageCheck = await checkAiUsageLimit(req.user.email || req.user.googleId || req.user._id);
    if (!usageCheck.allowed) {
      return res.status(429).json({
        error: usageCheck.reason,
        requiresPro: usageCheck.requiresPro || false,
        upgradeUrl: "/payment"
      });
    }

    const { code, language, analysisType = 'general' } = req.body;

    if (!code) {
      return res.status(400).json({ error: "Code is required" });
    }

    console.log(`AI Code Analysis request from ${req.user.email} (Pro user) - Type: ${analysisType}`);

    const aiModel = genAI.getGenerativeModel({ model: 'gemini-2.0-flash-exp' });

    let prompt = '';
    
    switch (analysisType) {
      case 'debug':
        prompt = `As an expert code analyzer for CodeCollab Pro, please analyze this ${language} code for potential bugs, errors, or issues:\n\n\`\`\`${language}\n${code}\n\`\`\`\n\nProvide specific suggestions for fixes and improvements. Include severity levels (Critical, High, Medium, Low) for each issue found.`;
        break;
      case 'optimize':
        prompt = `As an expert performance analyst for CodeCollab Pro, please analyze this ${language} code for performance optimizations and best practices:\n\n\`\`\`${language}\n${code}\n\`\`\`\n\nSuggest specific improvements for better performance, readability, and maintainability. Include before/after code examples where applicable.`;
        break;
      case 'explain':
        prompt = `As an expert code educator for CodeCollab Pro, please explain what this ${language} code does, line by line:\n\n\`\`\`${language}\n${code}\n\`\`\`\n\nProvide a clear explanation of the code's functionality, logic, and any design patterns used. Include complexity analysis if relevant.`;
        break;
      case 'security':
        prompt = `As an expert security analyst for CodeCollab Pro, please analyze this ${language} code for security vulnerabilities:\n\n\`\`\`${language}\n${code}\n\`\`\`\n\nIdentify potential security issues, provide severity ratings, and suggest secure coding practices.`;
        break;
      case 'refactor':
        prompt = `As an expert code architect for CodeCollab Pro, please suggest refactoring improvements for this ${language} code:\n\n\`\`\`${language}\n${code}\n\`\`\`\n\nProvide suggestions for better code structure, design patterns, and maintainability. Include refactored code examples.`;
        break;
      default:
        prompt = `As an expert code reviewer for CodeCollab Pro, please provide a comprehensive analysis of this ${language} code:\n\n\`\`\`${language}\n${code}\n\`\`\`\n\nInclude observations about code quality, potential issues, security considerations, performance implications, and suggestions for improvement.`;
    }

    const result = await aiModel.generateContent(prompt);
    const response = await result.response;
    const analysis = response.text();

    // Increment usage count
    await incrementAiUsage(req.user.email || req.user.googleId || req.user._id);

    res.json({
      analysis: analysis,
      analysisType: analysisType,
      language: language,
      timestamp: new Date().toISOString(),
      usage: {
        remaining: Math.max(0, usageCheck.remaining - 1),
        isPro: usageCheck.isPro
      }
    });

  } catch (error) {
    console.error("AI Analysis error:", error);
    res.status(500).json({ 
      error: "Failed to analyze code",
      details: error.message 
    });
  }
});

// Vercel debug page route
app.post("/api/ai-autocomplete", requireProSubscription, async (req, res) => {

  try {
    const { language, context, currentLine, cursorPosition, textBeforeCursor, fullCode, isShortInput, wordCount } = req.body;

    if (!language || !context) {
      return res.status(400).json({ error: "Language and context are required" });
    }

    console.log(`AI Autocomplete: "${textBeforeCursor}" (${wordCount} words) in ${language}`);

    const apiKey = process.env.GEMINI_API_KEY;
    
    if (!apiKey) {
      throw new Error("Gemini API key not configured");
    }

    // Enhanced prompt for better 1-4 word completions
    let prompt;
    
    if (isShortInput && wordCount <= 4) {
      // Special handling for short inputs (1-4 words)
      prompt = `You are an expert code completion AI. The user typed "${textBeforeCursor}" in ${language}. Analyze this input and provide intelligent code completions.

Context:
\`\`\`${language}
${context}
\`\`\`

Full file context (last 500 chars):
\`\`\`
${(fullCode || '').slice(-500)}
\`\`\`

For the input "${textBeforeCursor}", provide 3-5 smart completions as JSON array:

Instructions:
1. If it's a partial function/method name, complete with parameters
2. If it's a variable declaration, suggest appropriate assignments
3. If it's a control structure keyword, provide the full syntax
4. If it's an object/class reference, suggest methods/properties
5. Consider the existing code context for relevant suggestions

Each completion should have:
- "text": exact code to insert
- "label": short description for display
- "type": "function", "variable", "class", "keyword", "snippet", "method", "property"
- "description": what this completion does
- "insertText": code with $1, $2 placeholders for tab stops

Return ONLY the JSON array:`;
    } else {
      // Regular prompt for longer inputs
      prompt = `You are an AI code completion assistant. Provide intelligent code completions for the given context.

Language: ${language}
Current line: "${currentLine}"
Text before cursor: "${textBeforeCursor}"
Context:
\`\`\`${language}
${context}
\`\`\`

Provide 3-5 relevant code completions as a JSON array. Each completion should have:
- "text": the code to insert
- "label": display label for the suggestion
- "type": one of "method", "function", "class", "variable", "property", "keyword", "snippet"
- "description": brief description of what this completion does
- "insertText": exact text to insert (can include snippets with $1, $2 placeholders)

Focus on:
1. Context-aware completions based on the current code
2. Common patterns for the programming language
3. Method/property completions if there's a dot notation
4. Variable/function completions based on existing code
5. Language-specific keywords and constructs

Return only the JSON array, no other text.`;
    }

    // Call Gemini API with a more focused configuration for autocomplete
    const geminiResponse = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash-exp:generateContent?key=${apiKey}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        contents: [{
          parts: [{
            text: prompt
          }]
        }],
        generationConfig: {
          temperature: 0.3, // Lower temperature for more consistent completions
          topK: 20,
          topP: 0.8,
          maxOutputTokens: 512, // Smaller response for faster autocomplete
        },
        safetySettings: [
          {
            category: "HARM_CATEGORY_HARASSMENT",
            threshold: "BLOCK_MEDIUM_AND_ABOVE"
          },
          {
            category: "HARM_CATEGORY_HATE_SPEECH",
            threshold: "BLOCK_MEDIUM_AND_ABOVE"
          },
          {
            category: "HARM_CATEGORY_SEXUALLY_EXPLICIT",
            threshold: "BLOCK_MEDIUM_AND_ABOVE"
          },
          {
            category: "HARM_CATEGORY_DANGEROUS_CONTENT",
            threshold: "BLOCK_MEDIUM_AND_ABOVE"
          }
        ]
      })
    });

    if (!geminiResponse.ok) {
      const errorData = await geminiResponse.text();
      console.error('Gemini API error for autocomplete:', errorData);
      // Return empty suggestions instead of error for better UX
      return res.json({ suggestions: [] });
    }

    const geminiData = await geminiResponse.json();
    
    if (geminiData.candidates && geminiData.candidates[0] && geminiData.candidates[0].content) {
      const aiResponse = geminiData.candidates[0].content.parts[0].text;
      
      try {
        // Try to parse the JSON response
        const cleanResponse = aiResponse.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
        const suggestions = JSON.parse(cleanResponse);
        
        // Validate and sanitize suggestions
        const validSuggestions = Array.isArray(suggestions) ? suggestions.filter(s => 
          s && typeof s === 'object' && s.text && s.label
        ).slice(0, 5) : []; // Limit to 5 suggestions
        
        res.json({ 
          suggestions: validSuggestions,
          timestamp: new Date().toISOString()
        });
      } catch (parseError) {
        console.error('Failed to parse AI autocomplete response:', parseError);
        console.error('Raw response:', aiResponse);
        
        // Fallback: try to extract simple completions from the response
        const fallbackSuggestions = extractFallbackSuggestions(aiResponse, textBeforeCursor);
        res.json({ 
          suggestions: fallbackSuggestions,
          timestamp: new Date().toISOString()
        });
      }
    } else {
      console.error('Unexpected Gemini response structure for autocomplete:', geminiData);
      res.json({ suggestions: [] });
    }

  } catch (error) {
    console.error("AI Autocomplete error:", error);
    // Return empty suggestions instead of error for better UX
    res.json({ 
      suggestions: [],
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

// Helper function to extract fallback suggestions when JSON parsing fails
function extractFallbackSuggestions(response, textBeforeCursor, language) {
  const suggestions = [];
  const lines = response.split('\n');
  
  // Try to extract meaningful code suggestions from the response
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed && !trimmed.startsWith('//') && !trimmed.startsWith('/*') && trimmed.length > 0) {
      // Look for code-like patterns
      if (trimmed.includes('(') || trimmed.includes('.') || /^[a-zA-Z_][a-zA-Z0-9_]*$/.test(trimmed)) {
        let insertText = trimmed;
        let type = 'text';
        
        // Determine suggestion type based on content
        if (trimmed.includes('function') || trimmed.includes('def ')) {
          type = 'function';
        } else if (trimmed.includes('class ')) {
          type = 'class';
        } else if (trimmed.includes('if ') || trimmed.includes('for ') || trimmed.includes('while ')) {
          type = 'keyword';
        } else if (trimmed.includes('(')) {
          type = 'method';
        } else if (trimmed.includes('.')) {
          type = 'property';
        }
        
        suggestions.push({
          text: insertText,
          label: insertText.length > 50 ? insertText.substring(0, 50) + '...' : insertText,
          type: type,
          description: `AI suggestion for "${textBeforeCursor}"`,
          insertText: insertText
        });
        
        if (suggestions.length >= 5) break;
      }
    }
  }
  
  // If no good suggestions found, provide language-specific fallbacks
  if (suggestions.length === 0) {
    const fallbacks = getLanguageSpecificFallbacks(textBeforeCursor, language);
    suggestions.push(...fallbacks);
  }
  
  return suggestions;
}

// Get language-specific fallback suggestions
function getLanguageSpecificFallbacks(textBeforeCursor, language) {
  const suggestions = [];
  const input = textBeforeCursor.toLowerCase().trim();
  
  if (language === 'javascript' || language === 'typescript') {
    if (input.includes('func') || input === 'f') {
      suggestions.push({
        text: 'function ${1:name}(${2:params}) {\n\t${3:// code}\n\treturn ${4:value};\n}',
        label: 'function declaration',
        type: 'function',
        description: 'Create a function',
        insertText: 'function ${1:name}(${2:params}) {\n\t${3:// code}\n\treturn ${4:value};\n}'
      });
    }
    
    if (input.includes('const') || input === 'c') {
      suggestions.push({
        text: 'const ${1:name} = ${2:value};',
        label: 'const declaration',
        type: 'variable',
        description: 'Create a constant',
        insertText: 'const ${1:name} = ${2:value};'
      });
    }
    
    if (input.includes('if') || input === 'i') {
      suggestions.push({
        text: 'if (${1:condition}) {\n\t${2:// code}\n}',
        label: 'if statement',
        type: 'keyword',
        description: 'Create an if statement',
        insertText: 'if (${1:condition}) {\n\t${2:// code}\n}'
      });
    }
  } else if (language === 'python') {
    if (input.includes('def') || input === 'd') {
      suggestions.push({
        text: 'def ${1:function_name}(${2:params}):\n    """${3:docstring}"""\n    ${4:pass}',
        label: 'function definition',
        type: 'function',
        description: 'Create a Python function',
        insertText: 'def ${1:function_name}(${2:params}):\n    """${3:docstring}"""\n    ${4:pass}'
      });
    }
    
    if (input.includes('class') || input === 'cl') {
      suggestions.push({
        text: 'class ${1:ClassName}:\n    """${2:docstring}"""\n    \n    def __init__(self, ${3:params}):\n        ${4:pass}',
        label: 'class definition',
        type: 'class',
        description: 'Create a Python class',
        insertText: 'class ${1:ClassName}:\n    """${2:docstring}"""\n    \n    def __init__(self, ${3:params}):\n        ${4:pass}'
      });
    }
  }
  
  return suggestions;
}

// Vercel debug page route
app.get("/vercel-debug", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "vercel-debug.html"));
});

// Edit permission system
const roomPermissions = new Map(); // roomId -> { owner: userId, currentEditor: userId, editRequests: Set() }

// Initialize room permissions
function initializeRoomPermissions(roomId, ownerId) {
  if (!roomPermissions.has(roomId)) {
    roomPermissions.set(roomId, {
      owner: ownerId,
      currentEditor: ownerId, // Owner starts as editor
      editRequests: new Set()
    });
  }
}

// Check if user has edit permission
function hasEditPermission(roomId, userId) {
  const perms = roomPermissions.get(roomId);
  if (!perms) return false;
  return perms.currentEditor === userId;
}

// Get room owner
function getRoomOwner(roomId) {
  const perms = roomPermissions.get(roomId);
  return perms ? perms.owner : null;
}

// Get current editor
function getCurrentEditor(roomId) {
  const perms = roomPermissions.get(roomId);
  return perms ? perms.currentEditor : null;
}

// Grant edit permission
function grantEditPermission(roomId, newEditorId) {
  const perms = roomPermissions.get(roomId);
  if (perms) {
    perms.currentEditor = newEditorId;
    perms.editRequests.delete(newEditorId);
    return true;
  }
  return false;
}

// Request edit permission
function requestEditPermission(roomId, userId) {
  const perms = roomPermissions.get(roomId);
  if (perms) {
    perms.editRequests.add(userId);
    return true;
  }
  return false;
}

// Remove edit request
function removeEditRequest(roomId, userId) {
  const perms = roomPermissions.get(roomId);
  if (perms) {
    perms.editRequests.delete(userId);
  }
}

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
  socket.on("join_room", async (roomData) => {
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
      
      // Initialize room permissions - owner gets edit access
      initializeRoomPermissions(roomId, userId);
    } else {
      // For existing rooms, ensure permissions are initialized
      if (!roomPermissions.has(roomId)) {
        const existingRoom = activeRooms.get(roomId);
        initializeRoomPermissions(roomId, existingRoom.createdBy || userId);
      }
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

    // Check room capacity based on user subscription (only for new users)
    if (!userAlreadyInRoom) {
      try {
        // Get user data from database to check subscription
        const user = await safeDBOperation(async () => {
          return await collection.findOne({
            $or: [
              { email: userId.includes('@') ? userId : undefined },
              { googleId: userId },
              { _id: userId }
            ]
          });
        });

        const subscription = user?.subscription || { isPro: false };
        
        // Check if subscription has expired
        if (subscription.isPro && subscription.subscriptionEnd && new Date() > new Date(subscription.subscriptionEnd)) {
          subscription.isPro = false;
        }

        const maxCapacity = subscription.isPro ? 50 : 4; // Pro users get 50, free users get 4
        const currentUserCount = roomUsers.size;

        if (currentUserCount >= maxCapacity) {
          console.log(`Room ${roomId} is at capacity (${currentUserCount}/${maxCapacity})`);
          socket.emit("join_error", { 
            message: subscription.isPro ? 
              `Room is at maximum capacity (${maxCapacity} users)` :
              `Room is at free plan capacity (${maxCapacity} users). Upgrade to Pro for unlimited capacity.`,
            requiresPro: !subscription.isPro,
            upgradeUrl: "/payment"
          });
          return;
        }
      } catch (error) {
        console.error("Error checking user subscription for room capacity:", error);
        // Default to free limits on error
        if (roomUsers.size >= 4) {
          socket.emit("join_error", { 
            message: "Room is at capacity. Please try again later.",
            requiresPro: true
          });
          return;
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

    // Track room join in user activity
    if (!userAlreadyInRoom) {
      try {
        await safeDBOperation(async () => {
          await collection.updateOne(
            { 
              $or: [
                { email: userId.includes('@') ? userId : undefined },
                { googleId: userId },
                { _id: userId }
              ]
            },
            { 
              $inc: {
                "activity.roomsJoined": 1
              }
            }
          );
        });

        // Track activity
        const roomData = await safeDBOperation(async () => {
          return await Room.findOne({ roomId: roomId });
        });
        
        await trackUserActivity(
          userId, 
          'room_joined', 
          `Joined room: ${roomData?.name || roomId}`,
          `Collaboration session started`,
          { roomId, roomName: roomData?.name || roomId }
        );

      } catch (error) {
        console.error("Error tracking room join:", error);
      }
    }

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

    // Send existing users' information to the new user
    const existingUsers = [];
    for (const userData of roomUsers.values()) {
      if (userData.socketId !== socket.id) {
        existingUsers.push({
          userId: userData.userId,
          username: userData.username,
          picture: userData.picture,
          color: userData.color || getColorForUser(userData.userId),
          socketId: userData.socketId,
          timestamp: Date.now()
        });
      }
    }
    
    if (existingUsers.length > 0) {
      // Send existing users to the new user
      existingUsers.forEach(user => {
        socket.emit("existing_user", user);
      });
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
      currentEditor: getCurrentEditor(roomId),
      isOwner: getRoomOwner(roomId) === userId
    });

    // Send current room code to the new user
    try {
      const roomCode = await loadRoomCode(roomId);
      if (roomCode && roomCode.code) {
        socket.emit("current_code", {
          code: roomCode.code,
          language: roomCode.language || 'javascript',
          lastModified: roomCode.lastModified
        });
      }
    } catch (error) {
      console.error("Error loading room code for new user:", error);
    }

    console.log(
      `User ${username} (${socket.id}) joined room ${roomId} with ${roomUsers.size} total users`,
    );
  });

  // Handle code changes
  socket.on("code_change", async (data) => {
    const { roomId, code, language, userId, username, cursorPosition } = data;

    // Validate data
    if (!roomId || !userId || typeof code !== "string") {
      console.log(`Invalid code data from ${username || userId}`);
      return;
    }

    // Check edit permission
    const roomData = activeRooms.get(roomId);
    if (!roomData) {
      socket.emit("edit_denied", { message: "Room not found" });
      return;
    }

    // Check if user has permission to edit
    if (!hasEditPermission(roomId, userId)) {
      socket.emit("edit_denied", { 
        message: "You don't have permission to edit this file",
        currentEditor: roomData.currentEditor
      });
      return;
    }

    // Auto-save code to database
    try {
      await saveRoomCode(roomId, {
        code: code,
        language: language || 'javascript',
        lastModified: new Date(),
        lastModifiedBy: userId
      });
    } catch (error) {
      console.error("Error auto-saving code for room", roomId, ":", error);
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

  // Handle edit permission requests
  socket.on("request_edit_permission", (data) => {
    const { roomId, userId, username } = data;
    
    if (!roomId || !userId) {
      return;
    }

    const currentEditor = getCurrentEditor(roomId);
    const roomOwner = getRoomOwner(roomId);
    
    if (!currentEditor) {
      socket.emit("edit_denied", { message: "Room not found" });
      return;
    }

    // If requesting user is already the editor, no need to request
    if (currentEditor === userId) {
      socket.emit("edit_permission_granted", { 
        message: "You already have edit permission",
        isEditor: true 
      });
      return;
    }

    // Add to edit requests
    requestEditPermission(roomId, userId);

    // Get the socket of current editor to send the permission request
    const roomUsers = activeRooms.get(roomId);
    if (roomUsers) {
      for (const [socketId, userData] of roomUsers.entries()) {
        if (userData.userId === currentEditor) {
          // Send request to current editor
          io.to(socketId).emit("edit_permission_requested", {
            fromUserId: userId,
            fromUsername: username,
            roomId: roomId
          });
          break;
        }
      }
    }

    // Notify the requester that request was sent
    socket.emit("edit_request_sent", {
      message: `Edit request sent to ${currentEditor === roomOwner ? 'room owner' : 'current editor'}`,
      currentEditor: currentEditor
    });
  });

  // Handle edit permission responses
  socket.on("respond_edit_permission", (data) => {
    const { roomId, userId, grantedUserId, granted, username } = data;
    
    if (!roomId || !userId || !grantedUserId) {
      return;
    }

    const currentEditor = getCurrentEditor(roomId);
    
    // Only current editor can grant permissions
    if (currentEditor !== userId) {
      socket.emit("permission_denied", { message: "You don't have permission to grant edit access" });
      return;
    }

    const roomUsers = activeRooms.get(roomId);
    if (!roomUsers) {
      return;
    }

    // Find the user who requested permission
    let targetSocketId = null;
    let targetUsername = null;
    for (const [socketId, userData] of roomUsers.entries()) {
      if (userData.userId === grantedUserId) {
        targetSocketId = socketId;
        targetUsername = userData.username;
        break;
      }
    }

    if (granted && targetSocketId) {
      // Grant permission
      grantEditPermission(roomId, grantedUserId);
      
      // Notify the granted user
      io.to(targetSocketId).emit("edit_permission_granted", {
        message: "You have been granted edit permission",
        grantedBy: username,
        isEditor: true
      });

      // Notify all users about the editor change
      io.to(roomId).emit("editor_changed", {
        newEditor: grantedUserId,
        newEditorName: targetUsername,
        previousEditor: userId,
        previousEditorName: username
      });

      // Notify the previous editor they lost permission
      socket.emit("edit_permission_revoked", {
        message: "You have granted edit permission to " + targetUsername,
        newEditor: grantedUserId
      });

    } else if (targetSocketId) {
      // Deny permission
      removeEditRequest(roomId, grantedUserId);
      io.to(targetSocketId).emit("edit_permission_denied", {
        message: "Your edit request was denied",
        deniedBy: username
      });
    }
  });

  // Handle voluntary edit permission release
  socket.on("release_edit_permission", (data) => {
    const { roomId, userId } = data;
    
    if (!roomId || !userId) {
      return;
    }

    const currentEditor = getCurrentEditor(roomId);
    const roomOwner = getRoomOwner(roomId);
    
    // Only current editor can release permission
    if (currentEditor !== userId) {
      return;
    }

    // Release permission back to owner
    grantEditPermission(roomId, roomOwner);

    const roomUsers = activeRooms.get(roomId);
    if (roomUsers) {
      let ownerSocketId = null;
      let ownerName = null;
      for (const [socketId, userData] of roomUsers.entries()) {
        if (userData.userId === roomOwner) {
          ownerSocketId = socketId;
          ownerName = userData.username;
          break;
        }
      }

      if (ownerSocketId) {
        // Notify owner they got permission back
        io.to(ownerSocketId).emit("edit_permission_granted", {
          message: "Edit permission has been returned to you",
          isEditor: true
        });

        // Notify all users about the editor change
        io.to(roomId).emit("editor_changed", {
          newEditor: roomOwner,
          newEditorName: ownerName,
          previousEditor: userId,
          previousEditorName: roomUsers.get(socket.id)?.username || 'Unknown'
        });
      }
    }

    // Notify the user who released permission
    socket.emit("edit_permission_revoked", {
      message: "You have released edit permission",
      newEditor: roomOwner
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
  socket.on("run_code", async (data) => {
    const { roomId, code, language, userId, username, fileName } = data;

    if (!roomId || !code || !language) {
      return;
    }

    console.log(
      `Running ${language} code for user ${username} in room ${roomId}`,
    );

    // Get room name for better tracking
    let roomName = roomId;
    try {
      const roomData = await safeDBOperation(async () => {
        return await Room.findOne({ roomId: roomId });
      });
      roomName = roomData?.name || roomId;
    } catch (error) {
      console.error("Error getting room name:", error);
    }

    // Execute code asynchronously
    executeCode(code, language, fileName)
      .then(async (result) => {
        // Track code execution with real data
        if (userId) {
          try {
            await trackCodeExecution(
              userId, 
              code, 
              language, 
              roomId, 
              roomName, 
              result.executionTime || 0
            );
          } catch (error) {
            console.error("Error tracking code execution:", error);
          }
        }

        // Send result back to the room
        io.to(roomId).emit("code_result", {
          result: result.output,
          error: result.error,
          language,
          userId,
          username,
          fileName,
          timestamp: Date.now(),
          executionTime: result.executionTime
        });
      })
      .catch(async (error) => {
        // Still track failed execution
        if (userId) {
          try {
            await trackCodeExecution(
              userId, 
              code, 
              language, 
              roomId, 
              roomName, 
              0
            );
          } catch (trackError) {
            console.error("Error tracking failed code execution:", trackError);
          }
        }

        // Send error back to the room
        io.to(roomId).emit("code_result", {
          result: null,
          error: error.message,
          language,
          userId,
          username,
          fileName,
          timestamp: Date.now()
        });
      });
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
  socket.on("file_saved", async (data) => {
    const { roomId, userId, username, fileName, fileIndex, fileContent, fileLanguage } = data;

    if (!roomId || !userId || !fileName) {
      return;
    }

    // Save file content to database
    if (fileContent) {
      try {
        await safeDBOperation(async () => {
          let room = await Room.findOne({ roomId: roomId });
          
          if (!room) {
            // Create room if it doesn't exist
            room = new Room({
              roomId: roomId,
              name: `Room ${roomId}`,
              currentCode: '',
              files: []
            });
          }

          // Update or add file
          const existingFileIndex = room.files.findIndex(f => f.name === fileName);
          
          if (existingFileIndex !== -1) {
            // Update existing file
            room.files[existingFileIndex] = {
              name: fileName,
              content: fileContent,
              language: fileLanguage || 'javascript',
              lastModified: new Date()
            };
          } else {
            // Add new file
            room.files.push({
              name: fileName,
              content: fileContent,
              language: fileLanguage || 'javascript',
              lastModified: new Date()
            });
          }

          room.lastModified = new Date();
          await room.save();
        });
      } catch (error) {
        console.error("Error saving file to database:", error);
      }
    }

    // Track file save activity
    if (userId && userId.includes('@')) {
      try {
        await trackUserActivity(
          userId, 
          'file_saved', 
          `Saved file: ${fileName}`,
          `File saved in room`,
          { roomId, fileName }
        );
        
        // Update coding session
        await updateCodingSession(userId);
      } catch (error) {
        console.error("Error tracking file save activity:", error);
      }
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
  socket.on("disconnect", async () => {
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
          // Handle edit permission cleanup
          const currentEditor = getCurrentEditor(roomId);
          const roomOwner = getRoomOwner(roomId);
          
          if (currentEditor === userId && roomOwner !== userId) {
            // Current editor left but is not owner - return permission to owner
            grantEditPermission(roomId, roomOwner);
            
            // Notify owner they got permission back
            const ownerSocket = findUserSocket(roomId, roomOwner);
            if (ownerSocket) {
              io.to(ownerSocket).emit("edit_permission_granted", {
                message: "Edit permission returned to you (previous editor left)",
                isEditor: true
              });

              // Notify all users about the editor change
              io.to(roomId).emit("editor_changed", {
                newEditor: roomOwner,
                newEditorName: findUserName(roomId, roomOwner) || 'Owner',
                previousEditor: userId,
                previousEditorName: username,
                reason: "Previous editor left the room"
              });
            }
          }

          // Remove any pending edit requests from this user
          removeEditRequest(roomId, userId);

          // Clean up voice chat participation
          try {
            await safeDBOperation(async () => {
              await VoiceChat.updateOne(
                { roomId: roomId },
                {
                  $pull: { participants: { socketId: socket.id } },
                  $set: { lastActivity: new Date() }
                }
              );
            });

            // Notify remaining voice chat participants
            socket.to(`voice_${roomId}`).emit("voice_user_left", {
              userId: userId,
              username: username,
              timestamp: Date.now()
            });
          } catch (error) {
            console.error("Error cleaning up voice chat on disconnect:", error);
          }

          // End coding session for this user
          if (userId && userId.includes('@')) {
            try {
              await endCodingSession(userId);
            } catch (error) {
              console.error("Error ending coding session on disconnect:", error);
            }
          }

          // If the room is empty, remove it and cleanup permissions
          if (users.size === 0) {
            activeRooms.delete(roomId);
            roomPermissions.delete(roomId);
          } else {
            // Notify others that the user left
            io.to(roomId).emit("user_left", {
              userId,
              username,
              userCount: users.size,
              timestamp: Date.now(),
              currentEditor: getCurrentEditor(roomId)
            });
          }
        }

        break; // Exit the loop once we've found and processed the room
      }
    }
  });

  // Handle request for current code
  socket.on("request_current_code", async (data) => {
    const { roomId } = data;
    
    try {
      const roomCode = await loadRoomCode(roomId);
      if (roomCode) {
        socket.emit("current_code", {
          code: roomCode.code || '',
          language: roomCode.language || 'javascript',
          lastModified: roomCode.lastModified
        });
      }
    } catch (error) {
      console.error("Error loading room code:", error);
      socket.emit("current_code", { code: '', language: 'javascript' });
    }
  });

  // Helper function to find user's socket ID
  function findUserSocket(roomId, userId) {
    const roomUsers = activeRooms.get(roomId);
    if (!roomUsers) return null;
    
    for (const [socketId, userData] of roomUsers.entries()) {
      if (userData.userId === userId) {
        return socketId;
      }
    }
    return null;
  }

  // Helper function to find user's name
  function findUserName(roomId, userId) {
    const roomUsers = activeRooms.get(roomId);
    if (!roomUsers) return null;
    
    for (const [socketId, userData] of roomUsers.entries()) {
      if (userData.userId === userId) {
        return userData.username;
      }
    }
    return null;
  }

  // ============== VOICE CHAT SIGNALING EVENTS ==============

  // Handle joining voice chat
  socket.on("join_voice_chat", async (data) => {
    const { roomId, userId, username } = data;

    if (!roomId || !userId || !username) {
      return;
    }

    console.log(`User ${username} attempting to join voice chat in room ${roomId}`);

    try {
      // Check if user has pro subscription or trial time
      const user = await safeDBOperation(async () => {
        return await collection.findOne({ 
          $or: [
            { email: userId },
            { googleId: userId },
            { githubId: userId },
            { _id: userId }
          ]
        });
      });

      if (!user) {
        console.log(`User ${username} not found in database`);
        socket.emit("voice_join_error", { 
          message: "User not found. Please sign in again.",
          requiresPro: false
        });
        return;
      }

      // Check subscription status
      const subscription = user.subscription || { isPro: false, planType: 'free' };
      
      // Check if subscription has expired
      if (subscription.isPro && subscription.subscriptionEnd && new Date() > new Date(subscription.subscriptionEnd)) {
        subscription.isPro = false;
      }

      // Voice chat access logic
      if (!subscription.isPro) {
        // Check trial usage for free users
        const voiceTrial = user.subscription?.limits?.voiceChatTrial || {
          totalMinutesUsed: 0,
          hasUsedTrial: false,
          trialStartDate: null
        };

        const TRIAL_LIMIT_MINUTES = 60; // 1 hour trial

        if (voiceTrial.totalMinutesUsed >= TRIAL_LIMIT_MINUTES) {
          console.log(`User ${username} has exhausted voice chat trial (${voiceTrial.totalMinutesUsed} minutes used)`);
          socket.emit("voice_join_error", { 
            message: `You've used your 1-hour Voice Chat trial (${voiceTrial.totalMinutesUsed} minutes). Upgrade to Pro for unlimited voice communication!`,
            requiresPro: true,
            feature: "voice_chat",
            trialExhausted: true,
            trialUsed: voiceTrial.totalMinutesUsed,
            trialLimit: TRIAL_LIMIT_MINUTES
          });
          return;
        }

        // Initialize trial if first time
        if (!voiceTrial.hasUsedTrial) {
          await collection.updateOne(
            { _id: user._id },
            {
              $set: {
                'subscription.limits.voiceChatTrial.hasUsedTrial': true,
                'subscription.limits.voiceChatTrial.trialStartDate': new Date()
              }
            }
          );
          console.log(`Voice chat trial initialized for user ${username}`);
        }

        // Start tracking current session
        await collection.updateOne(
          { _id: user._id },
          {
            $set: {
              'subscription.limits.voiceChatTrial.currentSessionStart': new Date()
            }
          }
        );

        const remainingMinutes = TRIAL_LIMIT_MINUTES - voiceTrial.totalMinutesUsed;
        console.log(`Free user ${username} joining voice chat with ${remainingMinutes} minutes remaining in trial`);
        
        // Emit trial info to client
        socket.emit("voice_trial_status", {
          isTrialUser: true,
          remainingMinutes: remainingMinutes,
          totalTrialMinutes: TRIAL_LIMIT_MINUTES,
          usedMinutes: voiceTrial.totalMinutesUsed
        });
      } else {
        console.log(`Pro user ${username} verified for unlimited voice chat access`);
      }

      // Find or create voice chat room
      let voiceRoom = await safeDBOperation(async () => {
        return await VoiceChat.findOne({ roomId: roomId });
      });

      if (!voiceRoom) {
        // Create new voice chat room
        voiceRoom = await safeDBOperation(async () => {
          const newVoiceRoom = new VoiceChat({
            roomId: roomId,
            participants: []
          });
          return await newVoiceRoom.save();
        });
      }

      // Check if user is already in voice chat
      const existingParticipant = voiceRoom.participants.find(p => p.userId === userId);

      if (!existingParticipant) {
        // Add user to voice chat
        await safeDBOperation(async () => {
          await VoiceChat.updateOne(
            { roomId: roomId },
            {
              $push: {
                participants: {
                  userId: userId,
                  username: username,
                  picture: user.picture || null,
                  socketId: socket.id,
                  isMuted: false,
                  isDeafened: false,
                  joinedAt: new Date()
                }
              },
              $set: { lastActivity: new Date() }
            }
          );
        });
      } else {
        // Update existing participant's socket ID and profile picture
        await safeDBOperation(async () => {
          await VoiceChat.updateOne(
            { roomId: roomId, "participants.userId": userId },
            {
              $set: {
                "participants.$.socketId": socket.id,
                "participants.$.picture": user.picture || null,
                "participants.$.isMuted": false,
                "participants.$.isDeafened": false,
                lastActivity: new Date()
              }
            }
          );
        });
      }

      // Join voice chat socket room
      socket.join(`voice_${roomId}`);

      // Get updated participant list
      const updatedVoiceRoom = await safeDBOperation(async () => {
        return await VoiceChat.findOne({ roomId: roomId });
      });

      // Send existing voice chat users to the newly joined user
      const existingVoiceUsers = updatedVoiceRoom.participants.filter(p => p.userId !== userId);
      if (existingVoiceUsers.length > 0) {
        existingVoiceUsers.forEach(existingUser => {
          socket.emit("existing_voice_user", {
            userId: existingUser.userId,
            username: existingUser.username,
            picture: existingUser.picture || null,
            isMuted: existingUser.isMuted,
            isDeafened: existingUser.isDeafened
          });
        });
      }

      // Notify all participants about the new user
      io.to(`voice_${roomId}`).emit("voice_user_joined", {
        userId: userId,
        username: username,
        participants: updatedVoiceRoom.participants.map(p => ({
          userId: p.userId,
          username: p.username,
          picture: p.picture || null,
          isMuted: p.isMuted,
          isDeafened: p.isDeafened
        })),
        timestamp: Date.now()
      });

      // Notify the joining user of success
      socket.emit("voice_join_success", {
        roomId: roomId,
        participants: updatedVoiceRoom.participants.map(p => ({
          userId: p.userId,
          username: p.username,
          picture: p.picture || null,
          isMuted: p.isMuted,
          isDeafened: p.isDeafened
        }))
      });

    } catch (error) {
      console.error("Error joining voice chat:", error);
      socket.emit("voice_join_error", { message: "Failed to join voice chat" });
    }
  });

  // Handle leaving voice chat
  socket.on("leave_voice_chat", async (data) => {
    const { roomId, userId, username } = data;

    if (!roomId || !userId) {
      return;
    }

    console.log(`User ${username || userId} leaving voice chat in room ${roomId}`);

    try {
      // Track usage time for free users
      const user = await safeDBOperation(async () => {
        return await collection.findOne({ 
          $or: [
            { email: userId },
            { googleId: userId },
            { githubId: userId },
            { _id: userId }
          ]
        });
      });

      if (user && user.subscription?.limits?.voiceChatTrial?.currentSessionStart) {
        const sessionStart = new Date(user.subscription.limits.voiceChatTrial.currentSessionStart);
        const sessionEnd = new Date();
        const sessionMinutes = Math.floor((sessionEnd - sessionStart) / (1000 * 60));

        if (sessionMinutes > 0) {
          // Update total minutes used
          await safeDBOperation(async () => {
            await collection.updateOne(
              { _id: user._id },
              {
                $inc: {
                  'subscription.limits.voiceChatTrial.totalMinutesUsed': sessionMinutes
                },
                $unset: {
                  'subscription.limits.voiceChatTrial.currentSessionStart': ''
                }
              }
            );
          });

          const totalUsed = (user.subscription.limits.voiceChatTrial.totalMinutesUsed || 0) + sessionMinutes;
          console.log(`User ${username} used ${sessionMinutes} minutes of voice chat trial (total: ${totalUsed}/60 minutes)`);

          // Notify user about remaining time
          const remaining = Math.max(0, 60 - totalUsed);
          socket.emit("voice_trial_update", {
            sessionMinutes: sessionMinutes,
            totalUsed: totalUsed,
            remainingMinutes: remaining
          });
        }
      }

      // Remove user from voice chat
      await safeDBOperation(async () => {
        await VoiceChat.updateOne(
          { roomId: roomId },
          {
            $pull: { participants: { userId: userId } },
            $set: { lastActivity: new Date() }
          }
        );
      });

      // Leave voice chat socket room
      socket.leave(`voice_${roomId}`);

      // Get updated participant list
      const updatedVoiceRoom = await safeDBOperation(async () => {
        return await VoiceChat.findOne({ roomId: roomId });
      });

      // Notify remaining participants
      if (updatedVoiceRoom && updatedVoiceRoom.participants.length > 0) {
        socket.to(`voice_${roomId}`).emit("voice_user_left", {
          userId: userId,
          username: username,
          participants: updatedVoiceRoom.participants.map(p => ({
            userId: p.userId,
            username: p.username,
            picture: p.picture || null,
            isMuted: p.isMuted,
            isDeafened: p.isDeafened
          })),
          timestamp: Date.now()
        });
      } else {
        // If no participants left, clean up the voice room
        await safeDBOperation(async () => {
          await VoiceChat.deleteOne({ roomId: roomId });
        });
      }

      // Confirm leave to the user
      socket.emit("voice_leave_success", { roomId: roomId });

    } catch (error) {
      console.error("Error leaving voice chat:", error);
    }
  });

  // Handle WebRTC offer
  socket.on("webrtc_offer", (data) => {
    const { roomId, offer, targetUserId, fromUserId } = data;

    if (!roomId || !offer || !targetUserId || !fromUserId) {
      return;
    }

    // Forward offer to target user in the same voice chat room
    socket.to(`voice_${roomId}`).emit("webrtc_offer_received", {
      offer: offer,
      fromUserId: fromUserId,
      targetUserId: targetUserId
    });
  });

  // Handle WebRTC answer
  socket.on("webrtc_answer", (data) => {
    const { roomId, answer, targetUserId, fromUserId } = data;

    if (!roomId || !answer || !targetUserId || !fromUserId) {
      return;
    }

    // Forward answer to target user in the same voice chat room
    socket.to(`voice_${roomId}`).emit("webrtc_answer_received", {
      answer: answer,
      fromUserId: fromUserId,
      targetUserId: targetUserId
    });
  });

  // Handle ICE candidate
  socket.on("webrtc_ice_candidate", (data) => {
    const { roomId, candidate, targetUserId, fromUserId } = data;

    if (!roomId || !candidate || !targetUserId || !fromUserId) {
      return;
    }

    // Forward ICE candidate to target user in the same voice chat room
    socket.to(`voice_${roomId}`).emit("webrtc_ice_candidate_received", {
      candidate: candidate,
      fromUserId: fromUserId,
      targetUserId: targetUserId
    });
  });

  // Handle mute toggle
  socket.on("voice_mute_toggle", async (data) => {
    const { roomId, userId, isMuted } = data;

    if (!roomId || !userId || typeof isMuted !== 'boolean') {
      return;
    }

    try {
      // Update mute status in database
      await safeDBOperation(async () => {
        await VoiceChat.updateOne(
          { roomId: roomId, "participants.userId": userId },
          {
            $set: {
              "participants.$.isMuted": isMuted,
              lastActivity: new Date()
            }
          }
        );
      });

      // Broadcast mute status to other participants
      socket.to(`voice_${roomId}`).emit("voice_user_muted", {
        userId: userId,
        isMuted: isMuted,
        timestamp: Date.now()
      });

    } catch (error) {
      console.error("Error toggling mute status:", error);
    }
  });

  // Handle deafen toggle
  socket.on("voice_deafen_toggle", async (data) => {
    const { roomId, userId, isDeafened } = data;

    if (!roomId || !userId || typeof isDeafened !== 'boolean') {
      return;
    }

    try {
      // Update deafen status in database
      await safeDBOperation(async () => {
        await VoiceChat.updateOne(
          { roomId: roomId, "participants.userId": userId },
          {
            $set: {
              "participants.$.isDeafened": isDeafened,
              lastActivity: new Date()
            }
          }
        );
      });

      // Broadcast deafen status to other participants
      socket.to(`voice_${roomId}`).emit("voice_user_deafened", {
        userId: userId,
        isDeafened: isDeafened,
        timestamp: Date.now()
      });

    } catch (error) {
      console.error("Error toggling deafen status:", error);
    }
  });

  // ============== END VOICE CHAT SIGNALING EVENTS ==============
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
      console.log("Server is listening on port:", port);
    })
    .on("error", handleServerError);
} else {
  console.log("Running in serverless environment, skipping server start");
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
