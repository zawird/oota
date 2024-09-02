package main

import (
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

	"github.com/ravener/discord-oauth2"
	"golang.org/x/oauth2"
)

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
		Scopes:       []string{discord.ScopeIdentify, discord.ScopeGuilds},
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
	req.Header.Set("Authorization", "Bot "+accessToken)

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

type User struct {
	ID string `json:"id"`
}

// Extract user ID from the JSON response
func extractUserID(body []byte) (string, error) {
	var user User
	if err := json.Unmarshal(body, &user); err != nil {
		return "", fmt.Errorf("error unmarshalling user JSON: %w", err)
	}
	if user.ID == "" {
		return "", errors.New("user ID not found in response")
	}
	return user.ID, nil
}

func main() {
	// Generate a secure state parameter
	state, err := generateState()
	if err != nil {
		log.Fatalf("Error generating state: %v", err)
	}

	oauth2Config := newOAuth2Config()

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

		// Extract the user ID from the response body (JSON parsing required)
		userID, err := extractUserID(body)
		if err != nil {
			log.Printf("Error extracting user ID: %v", err)
			http.Error(w, "Failed to extract user ID", http.StatusInternalServerError)
			return
		}

		// Extract the access token for checking guild membership
		accessToken := token.AccessToken
		inGuild, err := isUserInGuild(userID, accessToken)
		if err != nil {
			log.Printf("Error checking guild membership: %v", err)
			http.Error(w, "Failed to check guild membership", http.StatusInternalServerError)
			return
		}

		if !inGuild {
			// Redirect the user to join the Discord server
			joinURL := fmt.Sprintf("https://discord.com/oauth2/authorize?client_id=%s&scope=bot&guild_id=%s&response_type=code", oauth2Config.ClientID, os.Getenv("DISCORD_GUILD_ID"))
			http.Redirect(w, r, joinURL, http.StatusTemporaryRedirect)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write(body); err != nil {
			log.Printf("Error writing response: %v", err)
		}
	})

	server := &http.Server{Addr: ":3000"}

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
