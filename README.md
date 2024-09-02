# oota
Oauth of the Ancients

This Go server provides OAuth2 authentication for users via Discord, automatically adds them to a specified Discord server (guild), and manages user sessions using JWT tokens. The server is designed to integrate with a game to allow players to log in with their Discord accounts and maintain session persistence across game sessions.

## Features

- **Discord OAuth2 Authentication**: Allows users to log in using their Discord accounts.
- **Automatic Guild Join**: Automatically adds users to a specified Discord server if they are not already members.
- **Session Management**: Generates and verifies JWT tokens to maintain user sessions.
- **Whitelist Enforcement**: Ensures the bot only operates within a specified Discord server, automatically leaving any other server it is added to.

## Requirements

- **Go 1.16+**
- **Discord Bot**: A bot added to your Discord server with the appropriate permissions.
- **Render or similar hosting service**: For deploying the server.

## Setup

### 1. Clone the Repository

```bash
git clone https://github.com/zawird/oota.git
cd discord-oauth2-server
```

### 2. Setup Environment Variables

Create a '.env' file or set environment variables directly in your deployment platform:

```bash
DISCORD_CLIENT_ID=your-discord-client-id
DISCORD_CLIENT_SECRET=your-discord-client-secret
DISCORD_BOT_TOKEN=your-discord-bot-token
DISCORD_REDIRECT_URI=https://yourdomain.com/auth/callback
DISCORD_GUILD_ID=your-discord-guild-id
JWT_SECRET_KEY=your-random-secret-key
PORT=3000  
```

### 3. Generate a Secure JWT Secret Key

For the JWT_SECRET_KEY, you can generate a secure key using the following command in your terminal:

```bash
openssl rand -base64 32
```

### 4. Build and Run the Server

You can build and run the server locally for testing:

```bash
go build -o discord-oauth2-server
./discord-oauth2-server
```

Or simply run the server directly:

```bash
go run main.go
```

## Usage

### Login Process

1. When a user visits your game, they click the "Login" button.
2. The game opens the Discord OAuth2 login page.
3. After logging in, the user is redirected back to the server, where their membership in the specified Discord server is checked.
4. If the user is not already a member, the server automatically adds them to the server using the bot.
5. A JWT token is generated and stored as a cookie in the user's browser.
6. The user is redirected to the game, and their session is maintained using the JWT token.
   
### Handling Server Traffic

- The server listens on the port specified by the PORT environment variable, which is automatically provided by Render during deployment.
- The server uses the /auth/callback endpoint to handle the OAuth2 callback from Discord.
- 
### Security Considerations

- JWT Secret Key: Ensure your JWT_SECRET_KEY is kept secure and not hard-coded in your source code. Use environment variables.
- HTTPS: Always use HTTPS for your redirect URIs and server communication to protect sensitive data.
- 
## Troubleshooting

- Authentication Failed: If you encounter issues with the bot failing to authenticate, verify that the DISCORD_BOT_TOKEN is correct and that the bot has the necessary permissions in your Discord server.
- Port Binding Issues: Ensure your server is binding to the correct port provided by the PORT environment variable, especially when deploying to services like Render.
- Session Issues: If sessions are not persisting, check that the JWT token is being correctly set in and retrieved from the user's cookies.
  
## Contributing

If you encounter any issues or have suggestions for improvement, feel free to open an issue or submit a pull request.

## License

This project is licensed under the MIT License. See the [License](LICENSE) file for details.



