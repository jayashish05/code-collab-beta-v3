# CodeCollab - Real-time Collaborative Coding Platform

CodeCollab is an interactive, real-time collaborative coding platform that enables multiple users to code together simultaneously, chat, and share ideas in a seamless environment.

![CodeCollab Screenshot](https://i.imgur.com/1234567.png)

## Features

- **Real-time Collaboration**: Code together with teammates in real-time
- **Multiple Language Support**: JavaScript, Python, Java, C#, C++, PHP, Ruby, Go, Swift
- **Live Chat**: Communicate with team members while coding
- **Password Protected Rooms**: Secure your coding sessions
- **User Authentication**: Google OAuth and local authentication
- **Syntax Highlighting**: Clear code visualization with theme options
- **Responsive Design**: Works on desktop and mobile devices

## Tech Stack

- **Frontend**: HTML5, CSS3, JavaScript, Bootstrap 5
- **Backend**: Node.js, Express.js
- **Real-time Communication**: Socket.IO
- **Code Editor**: CodeMirror
- **Authentication**: Passport.js

## Getting Started

### Prerequisites

- Node.js (v14 or higher)
- npm or yarn

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
   PORT=3000
   SESSION_SECRET=your_session_secret
   GOOGLE_CLIENT_ID=your_google_client_id
   GOOGLE_CLIENT_SECRET=your_google_client_secret
   CALLBACK_URL=http://localhost:3000/auth/google/callback
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