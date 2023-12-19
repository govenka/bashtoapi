/*
 * BASH to API
 * Developped by : Christophe Delaigue
 *
 * Licence:
 * This project is licensed under the  GNU GENERAL PUBLIC LICENSE - see the LICENSE file for details.
 */

package main

import (
	"bytes"
	"flag"
	"fmt"
	//"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"gopkg.in/ini.v1"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

var jwtSecret = []byte("YourprivatefirstJWTToken")
var token string
var tokenMutex sync.Mutex
var commandWhitelist map[string]bool

func loadWhitelist() error {
    cfg, err := ini.Load("config.ini")
    if err != nil {
        return err
    }
    commands := cfg.Section("whitelist").Key("commands").String()
    commandList := strings.Split(commands, ", ")
    commandWhitelist = make(map[string]bool)
    for _, cmd := range commandList {
        commandWhitelist[cmd] = true
    }
    return nil
}

func GenerateToken() (string, error) {
	tk := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"exp": time.Now().Add(time.Hour * 1).Unix(),
	})

	return tk.SignedString(jwtSecret)
}

func GetCurrentToken() string {
	tokenMutex.Lock()
	defer tokenMutex.Unlock()
	return token
}

func GetToken(c *gin.Context) {
	currentToken := GetCurrentToken()
	c.JSON(http.StatusOK, gin.H{"token": currentToken})
}

func RenewToken() {
	for {
		time.Sleep(time.Minute * 55)

		newToken, err := GenerateToken()
		if err != nil {
			fmt.Println("Error renewing the token:", err)
			continue
		}

		tokenMutex.Lock()
		token = newToken
		tokenMutex.Unlock()
		fmt.Println("Token renewed:", newToken)
	}
}

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			c.JSON(http.StatusUnauthorized, "Authorization header format must be Bearer <token>")
			c.Abort()
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, "Invalid token")
			c.Abort()
			return
		}

		c.Next()
	}
}

func RunCommand(c *gin.Context) {
    var argsMap map[string]string

    if err := c.ShouldBindJSON(&argsMap); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    var command string
    var args []string
    for k, v := range argsMap {
        if command == "" {
            command = k
            if v != "" {
                args = strings.Split(v, " ")
            }
        } else {
            additionalArgs := strings.Split(v, " ")
            args = append(args, fmt.Sprintf("-%s", k))
            args = append(args, additionalArgs...)
        }
    }

    if command == "" {
        c.String(http.StatusBadRequest, "No command specified")
        return
    }

    cmd := exec.Command(command, args...)
    var stdout, stderr bytes.Buffer
    cmd.Stdout = &stdout
    cmd.Stderr = &stderr

    if err := cmd.Run(); err != nil {
        c.String(500, fmt.Sprintf("Command execution failed: %s", stderr.String()))
        return
    }

    c.String(200, stdout.String())
}


func UploadFile(c *gin.Context) {
	file, err := c.FormFile("file")
	directory := c.PostForm("directory")

	if err != nil {
		c.String(http.StatusBadRequest, fmt.Sprintf("upload file err: %s", err.Error()))
		return
	}

	if _, err := os.Stat(directory); os.IsNotExist(err) {
		os.MkdirAll(directory, 0755)
	}

	fullPath := filepath.Join(directory, file.Filename)

	if err := c.SaveUploadedFile(file, fullPath); err != nil {
		c.String(http.StatusBadRequest, fmt.Sprintf("save file err: %s", err.Error()))
		return
	}

	c.String(http.StatusOK, fmt.Sprintf("File %s uploaded successfully to %s", file.Filename, directory))
}

func main() {
	port := flag.String("port", "8080", "Port to run the server on")
	enableAuth := flag.Bool("enableAuth", true, "Enable JWT authentication")
	flag.Parse()

    // Load the whitelist
    err := loadWhitelist()
    if err != nil {
        fmt.Println("Failed to load the whitelist:", err)
        return
    }

	// Initialize the first token
	if *enableAuth {
		var err error
		token, err = GenerateToken()
		if err != nil {
			fmt.Println("Error generating the initial token:", err)
			return
		}

		// Start the goroutine to renew the token
		go RenewToken()
	}

	r := gin.Default()
	
	//CORS 
	r.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		// Handle browser preflight request for CORS
		if c.Request.Method == "OPTIONS" {
		        c.AbortWithStatus(204)
	        	return
		}

		c.Next()
	})
	// Route to get the token, no authentication middleware
	r.GET("/get-token", GetToken)

	if *enableAuth {
		// Group routes with authentication middleware
		authorized := r.Group("/")
		authorized.Use(AuthMiddleware())
		{
			authorized.POST("/run", RunCommand)
			authorized.POST("/upload", UploadFile)
		}
	} else {
		// If authentication is disabled, just add the routes normally
		r.POST("/run", RunCommand)
		r.POST("/upload", UploadFile)
	}

	fmt.Printf("Server started at :%s\n", *port)
	r.Run(":" + *port)
}
