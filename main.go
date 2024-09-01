package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
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

// Check if the user is a member of the specified server
func isUserInServer(client *http.Client, userID, serverID string) (bool, error) {
	url := "https://discord.com/api/v10/guilds/" + serverID + "/members/" + userID
	resp, err := client.Get(url)
	if err != nil {
		return false, err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Printf("Error closing response body: %v", closeErr)
		}
	}()

	if resp.StatusCode == http.StatusOK {
		return true, nil
	}
	return false, nil
}

func main() {
	// Generate a secure state parameter
	state, err := generateState()
	if err != nil {
		log.Fatalf("Error generating state: %v", err)
	}

	oauth2Config := newOAuth2Config()
	serverID := os.Getenv("DISCORD_SERVER_ID")

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

		var userInfo map[string]interface{}
		if err := json.Unmarshal(body, &userInfo); err != nil {
			log.Printf("Error unmarshalling user info: %v", err)
			http.Error(w, "Failed to parse user info", http.StatusInternalServerError)
			return
		}

		userID, ok := userInfo["id"].(string)
		if !ok {
			http.Error(w, "Failed to get user ID", http.StatusInternalServerError)
			return
		}

		isMember, err := isUserInServer(client, userID, serverID)
		if err != nil {
			log.Printf("Error checking server membership: %v", err)
			http.Error(w, "Failed to check server membership", http.StatusInternalServerError)
			return
		}

		if !isMember {
			http.Error(w, "You must join the specified Discord server to access this application.", http.StatusForbidden)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write(body); err != nil {
			log.Printf("Error writing response: %v", err)
		}
	})

	// Use the port provided by the environment variable or default to 8080
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
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
