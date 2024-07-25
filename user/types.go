package user

type User struct {
	Id       int64
	Name     string
	Email    string
	Passwd   string
	Verified bool
	CDate    int64
}
