# GoLang Server with JWT Authentication to convert bash commands to secured API
### Developed by: Christophe Delaigue

## Overview

This GoLang project implements a simple HTTP server using the Gin framework, featuring JWT (JSON Web Token), authentication, and various endpoints to use token generation, bash command execution, file upload functionalities, and bash commands whitelist management. 

## Features

- **JWT Token Generation and Renewal:** Secure token generation for authentication, with an automatic renewal mechanism.
- **Command Execution:** Allows executing predefined commands on the server with dynamic arguments.
- **File Upload:** Endpoint to upload files to a specified directory.
- **CORS Enabled:** Configured to handle Cross-Origin Resource Sharing (CORS), making it suitable for web applications.
- **Configurable Port and Authentication:** Launch the server on a custom port and toggle JWT authentication.

## Getting Started

### Prerequisites

- GoLang installed on your system.
- Basic understanding of GoLang and HTTP servers.

### Installation

1. Clone the repository to your local machine.
2. Navigate to the project directory.
3. Install the required GoLang packages.

   ```shell
   go mod init bashtoapi

   go get -u github.com/gin-gonic/gin
   go get -u github.com/dgrijalva/jwt-go
   go get gopkg.in/ini.v1

   go build apigateway.go 
Usage

Start and use the server:
``` 
user>./apigateway -h
user>./apigateway -port 8080 &

user>curl http://localhost:8080/get-token
{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MDI5ODMxMjR9.3qZiYzM7dKox-ATDy67rnAFU5y3X6TTV1h63TpxkL3M"}

user> curl -X POST http://localhost:8080/run \
-H "API-Key: APIKEY1" \
-H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MDI5ODMxMjR9.3qZiYzM7dKox-ATDy67rnAFU5y3X6TTV1h63TpxkL3M" \
-H "Content-Type: application/json" \
-d '{"echo": "hello"}'
hello

Execute ls -l in the current directory : 
user>curl -X POST http://localhost:8080/run -H "API-Key: APIKEY1" -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MDI5ODMxMjR9.3qZiYzM7dKox-ATDy67rnAFU5y3X6TTV1h63TpxkL3M" -H "Content-Type: application/json" -d '{"ls": "-l"}'

user> curl -X POST http://localhost:8080/run -H "API-Key: APIKEY1" -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MDI5ODMxMjR9.3qZiYzM7dKox-ATDy67rnAFU5y3X6TTV1h63TpxkL3M" -H "Content-Type: application/json" -d '{"ls": "-l /home -a"}'
```

## Whitelist Command Management System
Our application includes a whitelist mechanism to enhance security when executing commands through the API. This system ensures that only explicitly allowed commands can be executed, thereby minimizing the security risks associated with running arbitrary commands.

How the Whitelist Works
The whitelist is managed through a config.ini configuration file. In this file, allowed commands are defined under a specific section [whitelist]. Only commands listed in this file can be executed by the API. Any attempt to execute a command not listed will result in a denial.

### Configuring the Whitelist
To configure the whitelist, follow these steps:

Open the config.ini file: This file is located in the root directory of the application.
Add your allowed commands: Under the [whitelist] section, add the commands you wish to permit, separated by commas. For example:

```
[whitelist]
commands = echo, ls
[api_keys]
key1 = APIKEY1
key2 = APIKEY2
key3 = APIKEY3
```

This configuration allows the echo and ls commands. You can also add in this file all API keys needed

Usage Example
With the above whitelist configuration, if you want to execute the command ls -l /home via the API, your request should look like:

```
{
    "ls": "-l /home"
}
```

This request will be accepted and executed because ls is on the whitelist. Conversely, a command like rm will be rejected if it is not specified in config.ini.

It is crucial to manage the list of allowed commands carefully. Including powerful or sensitive commands can increase the security risk to the system. It is recommended to limit the list to strictly necessary commands and regularly monitor API usage for any suspicious activity.

## Optional flags:

-port: Specify the server port (default is 8080).
-enableAuth: Enable or disable JWT authentication (default is true).
Access the following endpoints:

GET /get-token: Retrieve the current JWT token.
POST /run: Execute a command on the server. Requires JWT authentication.
POST /upload: Upload a file to a specified directory. Requires JWT authentication.
Configuration
Configure the JWT secret and server settings in the main function.
Modify the command path in RunCommand function as per your requirements.
Security
This application uses JWT for authentication. Ensure to keep the JWT secret secure and regularly update it for better security.

Contributing
Feel free to fork this repository and submit pull requests for enhancements.

License
This project is licensed under the  GNU GENERAL PUBLIC LICENSE - see the LICENSE file for details.
