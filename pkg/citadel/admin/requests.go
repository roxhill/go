package admin

type CreateUserRequest struct {
	UserId       string `json:"userId"`
	Username     string `json:"username"`
	EmailAddress string `json:"emailAddress"`
	Status       string `json:"status"`
	Language     string `json:"language"`
	Password     string `json:"password"`
}

type AdminMigrateBcryptUsersRequest struct {
	Items []BcryptUserMigrationRequest `json:"items"`
}

type DeleteUserMetadataRequest struct {
	UserId   string   `json:"userId"`
	Metadata []string `json:"metadata"`
}

type SetUserMetadataRequest struct {
	UserId   string         `json:"userId"`
	Metadata []MetadataItem `json:"metadata"`
}

type GetAllUserMetadataRequest struct {
	UserId string `json:"userId"`
}

type SetUserPasswordRequest struct {
	UserId   string `json:"userId"`
	Password string `json:"password"`
}

type UpdateUserRequest struct {
	UserId       string `json:"userId"`
	Username     string `json:"username,omitempty"`
	EmailAddress string `json:"emailAddress,omitempty"`
	PhoneNumber  string `json:"phoneNumber,omitempty"`
	Status       string `json:"status,omitempty"`
}

type ListUsersRequest struct {
	Cursor string `json:"cursor,omitempty"`
	Limit  int    `json:"limit"`
}

type DeleteUserRequest struct {
	UserId string `json:"userId"`
}

type GetUserRequest struct {
	UserId string `json:"userId"`
}

type AdminMigrateSha512UsersRequest struct {
	Items []Sha512UserMigrationRequest `json:"items"`
}

type Sha512UserMigrationRequest struct {
	UserId       string         `json:"userId"`
	Username     string         `json:"username"`
	EmailAddress string         `json:"emailAddress"`
	PhoneNumber  string         `json:"phoneNumber,omitempty"`
	Status       string         `json:"status"`
	Password     Sha512Password `json:"password"`
	Language     string         `json:"language"`
}

type Sha512Password struct {
	Algorithm  string `json:"alg"`
	Hash       string `json:"hash"`
	Salt       string `json:"salt"`
	Iterations int    `json:"iterations"`
}

type BcryptUserMigrationRequest struct {
	UserId       string         `json:"userId"`
	Username     string         `json:"username"`
	EmailAddress string         `json:"emailAddress"`
	PhoneNumber  string         `json:"phoneNumber,omitempty"`
	Status       string         `json:"status"`
	Password     BcryptPassword `json:"password"`
	Language     string         `json:"language"`
}

type AdminImpersonateStopRequest struct {
	Sid string `json:"sid"`
}

type AdminImpersonateStartRequest struct {
	Sid    string `json:"sid"`
	UserId string `json:"userId"`
}
