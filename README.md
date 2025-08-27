# CodeCollab - Real-time Collaborative Coding Platform

CodeCollab is an interactive, real-time collaborative coding platform that enables multiple users to code together simultaneously, chat, and share ideas in a seamless environment with AI Intergration.

Screenshots:

<img width="1470" height="956" alt="Screenshot 2025-08-11 at 2 44 18 AM" src="https://github.com/user-attachments/assets/0a8cf901-161b-4793-8ec3-3dd7105590c9" />

<img width="1470" height="956" alt="Screenshot 2025-08-11 at 2 44 30 AM" src="https://github.com/user-attachments/assets/c8e47a11-161c-469f-aefa-0b30ec7b5ef6" />

<img width="1470" height="956" alt="Screenshot 2025-08-11 at 2 44 34 AM" src="https://github.com/user-attachments/assets/0ff1c8bd-13fb-4b7e-8566-52aaf713ae68" />

<img width="1470" height="956" alt="Screenshot 2025-08-11 at 2 44 43 AM" src="https://github.com/user-attachments/assets/a3d69b8e-2bf0-4810-b93b-1c2b71b11da5" />

## Features

### Free Features
- **Real-time Collaboration**: Code together with teammates in real-time
- **Multiple Language Support**: JavaScript, Python, Java, C#, C++, PHP, Ruby, Go, Swift
- **Live Chat**: Communicate with team members while coding
- **Password Protected Rooms**: Secure your coding sessions
- **User Authentication**: Google OAuth and local authentication with password reset
- **Forgot Password**: Email-based password reset functionality
- **Syntax Highlighting**: Clear code visualization with theme options
- **Responsive Design**: Works on desktop and mobile devices
- **Room Capacity**: Up to 4 members per room

### Pro Features (₹99/month)
- **🤖 AI Code Assistant**: Advanced AI-powered code analysis, debugging, and optimization
- **🎤 Voice Chat**: Real-time voice communication with team members
- **👥 Unlimited Room Capacity**: Host rooms with unlimited members
- **🛠️ Code Debugging**: AI-powered bug detection and fixing suggestions
- **📊 Code Optimization**: Performance analysis and improvement recommendations
- **💬 Code Explanation**: AI explains complex code snippets in simple terms
- **⚡ Priority Support**: Get faster help and exclusive updates

## Tech Stack

- **Frontend**: HTML5, CSS3, JavaScript, Bootstrap 5
- **Backend**: Node.js, Express.js
- **Database**: MongoDB with Mongoose
- **Real-time Communication**: Socket.IO
- **Code Editor**: Monaco Editor
- **Authentication**: Passport.js (Google OAuth, Local)
- **Payment Processing**: Razorpay
- **AI Integration**: Google Gemini AI

## Try it out here just by clicking this link: https://code-collab-beta-v3.onrender.com

## Getting Started

### Prerequisites

- Node.js (v14 or higher)
- npm or yarn
- MongoDB database
- Razorpay account (for payment processing)
- Google API credentials (for OAuth)
- Google Gemini AI API key (for Pro features)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/jayashish05/Code-Collab-Beta-v1.git
   cd Code-Collab-Beta-v1
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Create a `.env` file in the root directory with the following variables:
   ```
   # Database Configuration
   MONGODB_URI=mongodb://localhost:27017/codecollab

   # Session Configuration
   SESSION_SECRET=your_session_secret_here

   # Google OAuth Configuration
   CLIENT_ID=your_google_client_id
   CLIENT_GOOGLE_SECRET=your_google_client_secret
   GOOGLE_CALLBACK_URL=http://localhost:3002/auth/google/callback

   # AI Configuration (for Pro features)
   GEMINI_API_KEY=your_gemini_api_key

   # Email Configuration (for password reset)
   EMAIL_USER=your_gmail_address
   EMAIL_PASS=your_gmail_app_password

   # Payment Configuration (Razorpay)
   RAZORPAY_KEY_ID=your_razorpay_key_id
   RAZORPAY_KEY_SECRET=your_razorpay_key_secret

   # Environment
   NODE_ENV=development
   PORT=3002
   ```

4. Start the development server:
   ```bash
   npm start
   ```

5. Open your browser and navigate to `http://localhost:3000`

## Usage

1. **Sign In/Register**: Use Google account or create a local account
2. **Dashboard**: View active rooms or create a new room
3. **Create Room**: Set room name, language, description, and optional password
4. **Join Room**: Click on any available room to join (password required if protected)
5. **Collaborate**: Code together, chat, and share ideas in real-time

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contact

Jayashish Muppur - [@jayashish05](https://github.com/jayashish05)

Project Link: [https://github.com/jayashish05/Code-Collab-Beta-v1](https://github.com/jayashish05/Code-Collab-Beta-v1)
