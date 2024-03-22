package admin

type BcryptPassword struct {
	Algorithm string `json:"alg"`
	Hash      string `json:"hash"`
}

type AdminMigrateUsersResponse struct {
	Items []UserId `json:"items"`
}

type UserId struct {
	UserId string `json:"userId"`
}

type DeleteUserMetadataResponse struct {
	Status string `json:"status"`
}

type SetUserMetadataResponse struct {
	Status string `json:"status"`
}

type GetAllUserMetadataResponse struct {
	Items []MetadataItem `json:"items"`
}

type MetadataItem struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type SetUserPasswordResponse struct {
	Status string `json:"status"`
}

type ListUsersResponse struct {
	Users  []UserResponse `json:"items"`
	Cursor string         `json:"cursor,omitempty"`
}

type DeleteUserResponse struct {
	Status string `json:"status"`
}

type UserResponse struct {
	UserId                 string   `json:"id"`
	AllowedAuthFlows       []string `json:"allowedAuthFlows"`
	RequiresPasswordChange bool     `json:"requiresPasswordChange"`
	Status                 string   `json:"status"`
	Username               string   `json:"username"`
	FailedPasswordAttempts int      `json:"failedPasswordAttempts"`
	Mfa                    bool     `json:"mfa"`
	EmailAddress           string   `json:"emailAddress"`
	EnabledMfaMethods      []string `json:"enabledMfaMethods"`
	Language               string   `json:"language"`
	PhoneNumber            string   `json:"phoneNumber"`
	CreatedByAdmin         bool     `json:"createdByAdmin"`
}

type CreateUserResponse struct {
	User UserResponse `json:"user"`
}

type AdminImpersonateStopResponse struct {
	Status string `json:"status"`
}

type AdminImpersonateStartResponse struct {
	Status string `json:"status"`
}
