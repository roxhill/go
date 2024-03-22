package client

type SessionResolveBearerResponse struct {
	Session ResolvedSession `json:"session,omitempty"`
}

type SessionRevokeBearerResponse struct {
	Status string `json:"status"`
}

type SessionRevokeResponse struct {
	ResponseHeaders map[string]string `json:"responseHeaders"`
}

type SessionResolveResponse struct {
	Session     ResolvedSession `json:"session,omitempty"`
	Recommended Recommended     `json:"recommended"`
}

type ResolvedIdentity struct {
	Id         string          `json:"id"`
	AssignedAt string          `json:"assignedAt"`
	User       string          `json:"user"`
	Data       []ResolvedValue `json:"data"`
	Status     string          `json:"status"`
}

type ResolvedValue struct {
	Name  string      `json:"name"`
	Value interface{} `json:"value"`
	From  string      `json:"from"`
}

type ResolvedSession struct {
	Id          string             `json:"id"`
	Sid         string             `json:"sid"`
	Identities  []ResolvedIdentity `json:"identities"`
	Audience    string             `json:"audience"`
	IssuedAt    string             `json:"issuedAt"`
	RefreshedAt string             `json:"refreshedAt"`
	ExpiresAt   string             `json:"expiresAt"`
	ResolvedAt  string             `json:"resolvedAt"`
}

type Recommended struct {
	Action          string      `json:"action"`
	ResponseHeaders interface{} `json:"responseHeaders"`
	Reason          string      `json:"reason"`
}
