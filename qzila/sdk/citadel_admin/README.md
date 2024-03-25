# Citadel Admin SDK

In order to manage users you need to use Admin SDK. Below is the simple example of how to instantiate the client with minimal config.

Once you have set up the client you can call any method on this client. Below is the example of getting the user info based on user id.

```go
package main

import (
	"fmt"
	citadel "github.com/everlutionsk/go/qzila/sdk/citadel_admin"
)

func main() {
	// set up the client
	client := citadel.NewClient(&citadel.ClientConfig{
		BaseUrl:      "https://{id}.execute-api.{region}.amazonaws.com/{stage}/admin/v1",
		ApiKey:       "will be provided to you",
		PreSharedKey: "will be provided to you",
	})

    // example of getting user info by id
	response, err := client.GetUser(&citadel.GetUserRequest{
		UserId: "some user id",
	})

	if err != nil {
		fmt.Printf("Failed: %v\n", err)
		return
	}
	fmt.Printf("Response:\n\n")
	fmt.Printf("%+v\n", response)
}
```
