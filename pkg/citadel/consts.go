package citadel

const (
	UserActive              = "active"
	UserDisabled            = "disabled"
	UserLocked              = "locked"
	UserInvited             = "invited"
	UserInvitationConfirmed = "invitationConfirmed"
)

const (
	AuthFlowEmailCode = "emailCode"
	AuthFlowPassword  = "password"
)

const (
	SecondFactorEmail      = "email"
	SecondFactorSms        = "sms"
	SecondFactorPrivateKey = "privateKey"
	SecondFactorTotp       = "totp"
)

const (
	LanguageEn = "en"
)

const (
	BcryptPasswordAlgorithm = "bcrypt"
	Sha512PasswordAlgorithm = "sha512"
)
