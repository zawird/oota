package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/bwmarrin/discordgo"
	"github.com/dgrijalva/jwt-go"
	"github.com/ravener/discord-oauth2"
	"golang.org/x/oauth2"
)

// JWT secret key (should be stored securely, e.g., in environment variables)
var jwtKey = []byte(os.Getenv("JWT_SECRET_KEY"))

// Claims JWT claims structure
type Claims struct {
	DiscordID string `json:"discord_id"`
	jwt.StandardClaims
}

// Securely generate a random state parameter
func generateState() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// Initialize the OAuth2 configuration
func newOAuth2Config() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     os.Getenv("DISCORD_CLIENT_ID"),
		ClientSecret: os.Getenv("DISCORD_CLIENT_SECRET"),
		RedirectURL:  os.Getenv("DISCORD_REDIRECT_URI"),
		Scopes:       []string{discord.ScopeIdentify, discord.ScopeGuildsJoin},
		Endpoint:     discord.Endpoint,
	}
}

// Check if the user is a member of the specified guild
func isUserInGuild(userID, accessToken string) (bool, error) {
	guildID := os.Getenv("DISCORD_GUILD_ID")
	url := fmt.Sprintf("https://discord.com/api/v10/guilds/%s/members/%s", guildID, userID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		if closeErr := res.Body.Close(); closeErr != nil {
			log.Printf("Error closing response body: %v", closeErr)
		}
	}()

	return res.StatusCode == http.StatusOK, nil
}

// Automatically join user to the server
func joinServer(userID, accessToken string) error {
	guildID := os.Getenv("DISCORD_GUILD_ID")
	url := fmt.Sprintf("https://discord.com/api/v10/guilds/%s/members/%s", guildID, userID)

	payload := map[string]string{
		"access_token": accessToken,
	}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bot "+os.Getenv("DISCORD_BOT_TOKEN"))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := res.Body.Close(); closeErr != nil {
			log.Printf("Error closing response body: %v", closeErr)
		}
	}()

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to add user to guild: %s", res.Status)
	}

	return nil
}

// Generate a JWT token for session management
func generateJWT(discordID string) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour) // Token valid for 24 hours
	claims := &Claims{
		DiscordID: discordID,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}

// Verify JWT token
func verifyJWT(tokenString string) (*Claims, error) {
	claims := &Claims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	return claims, nil
}

// Whitelist check to ensure bot only operates in your guild
func isGuildWhitelisted(guildID string) bool {
	return guildID == os.Getenv("DISCORD_GUILD_ID")
}

// Automatically leave any non-whitelisted server
func onGuildJoin(s *discordgo.Session, g *discordgo.GuildCreate) {
	if !isGuildWhitelisted(g.ID) {
		fmt.Println("Bot was added to a non-whitelisted server. Leaving...")
		if err := s.GuildLeave(g.ID); err != nil {
			fmt.Printf("Failed to leave guild %s: %v\n", g.ID, err)
		}
	}
}

// Simple "wake-up" handler
func handleWakeUp(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, err := w.Write([]byte("Server is awake"))
	if err != nil {
		return
	}
}

func main() {
	// Initialize Discord session
	dg, err := discordgo.New("Bot " + os.Getenv("DISCORD_BOT_TOKEN"))
	if err != nil {
		fmt.Println("error creating Discord session,", err)
		return
	}

	// Register the guild join handler
	dg.AddHandler(onGuildJoin)

	// Open a websocket connection to Discord
	err = dg.Open()
	if err != nil {
		fmt.Println("error opening connection,", err)
		return
	}

	// Generate a secure state parameter
	state, err := generateState()
	if err != nil {
		log.Fatalf("Error generating state: %v", err)
	}

	oauth2Config := newOAuth2Config()

	// Add the wake-up handler
	http.HandleFunc("/wake-up", handleWakeUp)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		url := oauth2Config.AuthCodeURL(state)
		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	})

	http.HandleFunc("/auth/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.FormValue("state") != state {
			http.Error(w, "State does not match.", http.StatusBadRequest)
			return
		}

		token, err := oauth2Config.Exchange(context.Background(), r.FormValue("code"))
		if err != nil {
			log.Printf("Error exchanging code for token: %v", err)
			http.Error(w, "Failed to exchange code for token", http.StatusInternalServerError)
			return
		}

		client := oauth2Config.Client(context.Background(), token)
		res, err := client.Get("https://discord.com/api/users/@me")
		if err != nil {
			log.Printf("Error getting user info: %v", err)
			http.Error(w, "Failed to get user info", http.StatusInternalServerError)
			return
		}
		defer func() {
			if closeErr := res.Body.Close(); closeErr != nil {
				log.Printf("Error closing response body: %v", closeErr)
			}
		}()

		if res.StatusCode != http.StatusOK {
			log.Printf("Error response from Discord: %s", res.Status)
			http.Error(w, "Received error response from Discord", http.StatusInternalServerError)
			return
		}

		body, err := io.ReadAll(res.Body)
		if err != nil {
			log.Printf("Error reading response body: %v", err)
			http.Error(w, "Failed to read response body", http.StatusInternalServerError)
			return
		}

		// Extract the user ID from the response body
		var user struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(body, &user); err != nil {
			log.Printf("Error unmarshalling user JSON: %v", err)
			http.Error(w, "Failed to extract user ID", http.StatusInternalServerError)
			return
		}

		// Check if the user is already in the guild
		inGuild, err := isUserInGuild(user.ID, token.AccessToken)
		if err != nil {
			log.Printf("Error checking if user is in guild: %v", err)
			http.Error(w, "Failed to check guild membership", http.StatusInternalServerError)
			return
		}

		// If the user is not in the guild, join them
		if !inGuild {
			if err := joinServer(user.ID, token.AccessToken); err != nil {
				log.Printf("Error adding user to server: %v", err)
				http.Error(w, "Failed to add user to server", http.StatusInternalServerError)
				return
			}
		}

		// Generate a JWT for the session
		jwtToken, err := generateJWT(user.ID)
		if err != nil {
			log.Printf("Error generating JWT: %v", err)
			http.Error(w, "Failed to generate session token", http.StatusInternalServerError)
			return
		}

		// Set the JWT as a cookie
		http.SetCookie(w, &http.Cookie{
			Name:    "session_token",
			Value:   jwtToken,
			Expires: time.Now().Add(24 * time.Hour),
		})

		// Redirect to the game or another protected resource
		http.Redirect(w, r, "/game", http.StatusFound)
	})

	http.HandleFunc("/game", func(w http.ResponseWriter, r *http.Request) {
		// Extract the session token from the cookie
		cookie, err := r.Cookie("session_token")
		if err != nil {
			if errors.Is(err, http.ErrNoCookie) {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		// Verify the session token
		claims, err := verifyJWT(cookie.Value)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// The user is authenticated; proceed with the game logic
		_, err = fmt.Fprintf(w, "Welcome to the game, user ID: %s", claims.DiscordID)
		if err != nil {
			return
		}
	})

	// Get the port from the environment, default to 3000 if not set
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}

	server := &http.Server{Addr: ":" + port}

	// Start server in a goroutine
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("ListenAndServe(): %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shut down the server
	sigint := make(chan os.Signal, 1)
	signal.Notify(sigint, os.Interrupt)

	<-sigint

	// Create a deadline to wait for existing connections to finish
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Server Shutdown Failed: %v", err)
	}

	log.Println("Server gracefully stopped")
}
