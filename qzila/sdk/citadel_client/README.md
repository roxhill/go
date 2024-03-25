# Citadel Client SDK

In order to resolve/revoke sessions you need to use Client SDK. Below is the simple example of how to instantiate the client with minimal config.

Once you have set up the client you can call any method on this client. Below is the example of resolving the session based on bearer token.

```go
package main

import (
	"fmt"
	citadel "github.com/everlutionsk/go/qzila/sdk/citadel_client"
)

func main() {
	// set up the client
	client := citadel.NewClient(&citadel.ClientConfig{
		BaseUrl:      "https://{id}.execute-api.{region}.amazonaws.com/{stage}/client/v1",
		PreSharedKey: "will be provided to you",
	})

	// example of resolving the session by bearer token
	response, err := client.SessionResolveBearer(&citadel.SessionResolveBearerRequest{
		Token: "token parsed from request",
	})

	if err != nil {
		fmt.Printf("Failed: %v\n", err)
		return
	}
	fmt.Printf("Response:\n\n")
	fmt.Printf("%+v\n", response)
}
```
