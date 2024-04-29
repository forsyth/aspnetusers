package aspnetusers

// maintain the aspnetusers table in the ASP.NET database, compatibly with simultaneous use by an ASP.NET Core application.

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/forsyth/pwdatav3"
	"github.com/go-sql-driver/mysql"
	"github.com/google/uuid" // roger peppe's fastuuid might be better now
)

// Database (perhaps "DatabaseHell" would be better) accounts for
// needless differences between SQL databases, notably the remarkable variation
// in inserted parameter syntax. It also provides inspection of
// driver-specific errors, because there is no standard error for the
// common case of trying to insert a duplicate key value.
type Database struct {

	// Param returns the string to be used for the n'th SQL command parameter.
	Param func(n int) string

	// BoolVar returns a location of the type used by the database to store a bool, iniitalised to false.
	BoolVar func() any

	// BoolVal returns the boolean value of a location returned by BoolVar.
	BoolVal func(a any) bool

	// IsDuplicate returns true iff the given error diagnoses an attempt to add a duplicate key value.
	IsDuplicate func(error) bool
}

// MySQLDatabase implements a database adapter for MySQL.
var MySQLDatabase = &Database{
	Param:   func(int) string { return "?" },
	BoolVar: func() any { return []uint8{0} },
	BoolVal: func(a any) bool { return a.([]uint8)[0] != 0 },
	IsDuplicate: func(err error) bool {
		if mysqlErr, ok := err.(*mysql.MySQLError); ok {
			// 1062 "duplicate value entered to a unique column" (in INSERT or UPDATE)
			return mysqlErr.Number == 1062
		}
		return false
	},
}

//
// if pgErr, ok := err.(*pq.Error); ok {
//	switch pgErr.Code.Name() {
//	case "foreign_key_violation", "unique_violation":
//		return true
//	default:
//		return false
//	}
//	return false
// }
// sqlserver uses @p1, @p2, ...

// Users provides access to the single database table containing registered users,
// usually called 'aspnetusers'.
type Users struct {
	db    *sql.DB
	table string    // database table name
	style *Database // database-specific conventions

	// SQL statements needed
	queryID   string
	queryName string
	insert    string
	update    string
}

// User represents a single entry in the ASP.NET-compatible database.
// Some strings can be NULL or DEFAULT NULL, but they become plain empty strings here,
// with no real loss of functionality. LockoutEnd was sometimes called LockoutEndUtc
// in some schemas, with a different date type. The Normalized fields did not exist in
// some older versions of ASP.NET.
type User struct {
	ID                   string     // the primary key for this user (UUID form)
	UserName             string     // the user name
	NormalizedUserName   string     // normalised user name
	Email                string     // email address
	NormalizedEmail      string     // normalised email address
	EmailConfirmed       bool       // has user confirmed email address?
	PasswordHash         string     // salted and hashed representation of password
	SecurityStamp        string     // random value that changes whenever credentials changed (password changed, login removed)
	ConcurrencyStamp     string     // a random value that must change when user entry stored/updated
	PhoneNumber          string     // user's phone number
	PhoneNumberConfirmed bool       // phone number has been confirmed
	TwoFactorEnabled     bool       // true iff two factor auth enabled
	LockoutEnd           *time.Time // optional time in UTC when user lockout ends (if past, not locked out)
	LockoutEnabled       bool       // can user be locked out?
	AccessFailedCount    int        // failed login attempts, up to system limit for lockout
}

var (
	// ErrNoPassword is returned if any call has an empty or completely blank password field.
	ErrNoPassword = errors.New("missing password")

	// ErrNotFound is returned if the key doesn't exist for the find operations.
	ErrNotFound = errors.New("user name not registered")

	// ErrExists is returned if the name (key) already exists.
	ErrExists = errors.New("user name already registered")

	// ErrConcurrency is returned if any update attempt detected that the underlying
	// record had been changed or deleted underfoot. Refetch the value to see what changed.
	ErrConcurrency = errors.New("clashing concurrent update")

	// ErrInvalidCredentials is returned if an authentication attempt failed,
	// owing to a non-existent user name or bad password.
	ErrInvalidCredentials = errors.New("invalid user name or password")

	// ErrLockedOut is returned by the optional check for a locked-out account.
	ErrLockedOut = errors.New("user account locked out")
)

var emptyHash = mustHashPassword("")

// NewUsers gives this package access to the ASP.NET users table (usually "aspnetusers")
// in the given database. SQL database implementations disagree on some essentials. The Database style
// parameter gives little functions to provide all that is needed here.
// It defaults to MySQLDatabase.
func New(db *sql.DB, table string, style *Database) *Users {
	if style == nil {
		style = MySQLDatabase
	}
	// TO DO: generate the statements
	return &Users{db: db, table: table, style: style}
}

// columns in lexical order excluding Id.
// As noted above, in ASP.NET the LockoutEnd field had several different names and types historically;
// LockoutEnd was that in use when this package was made.
var cols = []string{
	"AccessFailedCount", "ConcurrencyStamp", "Email", "EmailConfirmed", "LockoutEnabled", "LockoutEnd",
	"NormalizedEmail", "NormalizedUserName", "PasswordHash", "PhoneNumber",
	"PhoneNumberConfirmed", "SecurityStamp", "TwoFactorEnabled", "UserName",
}

func (tab *Users) unpackUser(row *sql.Row) (*User, error) {
	u := &User{}
	var concurrencyStamp, email, normalizedEmail, normalizedUserName sql.NullString
	var passwordHash, phoneNumber, securityStamp, userName sql.NullString
	var lockoutEnd sql.NullTime
	// MySQL lacks boolean type, uses numeric bit(1) or tinyint(1): must use an intermediate value
	// arguably the driver should be brighter, given there is sql.Bool
	emailConfirmed := tab.style.BoolVar()
	lockoutEnabled := tab.style.BoolVar()
	phoneNumberConfirmed := tab.style.BoolVar()
	twoFactorEnabled := tab.style.BoolVar()
	err := row.Scan(&u.ID,
		&u.AccessFailedCount,
		&concurrencyStamp,
		&email,
		&emailConfirmed,
		&lockoutEnabled,
		&lockoutEnd,
		&normalizedEmail,
		&normalizedUserName,
		&passwordHash,
		&phoneNumber,
		&phoneNumberConfirmed,
		&securityStamp,
		&twoFactorEnabled,
		&userName)
	if err != nil {
		return nil, err
	}
	u.ConcurrencyStamp = opts(&concurrencyStamp)
	u.Email = opts(&email)
	u.EmailConfirmed = tab.style.BoolVal(emailConfirmed)
	u.NormalizedEmail = opts(&normalizedEmail)
	u.NormalizedUserName = opts(&normalizedUserName)
	u.PasswordHash = opts(&passwordHash)
	u.PhoneNumber = opts(&phoneNumber)
	u.PhoneNumberConfirmed = tab.style.BoolVal(phoneNumberConfirmed)
	u.SecurityStamp = opts(&securityStamp)
	u.TwoFactorEnabled = tab.style.BoolVal(twoFactorEnabled)
	u.UserName = opts(&userName)
	u.LockoutEnabled = tab.style.BoolVal(lockoutEnabled)
	if lockoutEnd.Valid {
		u.LockoutEnd = &lockoutEnd.Time
	}
	return u, nil
}

// FindByID given a user's ID returns the database entry for a registered user, or an error.
// If the user does not exist, the error is exactly ErrNotFound.
func (tab *Users) FindByID(uid string) (*User, error) {
	stmt := tab.style.cmd("SELECT id,", cols, "FROM", tab.table, "WHERE Id = ", tab.style.Param(1))
	u, err := tab.unpackUser(tab.db.QueryRow(stmt, uid))
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("find user: %v", err)
	}
	return u, nil
}

// FindByName given a unique user name (typically now an email address) returns the database entry for a registered user, or an error.
// If the user does not exist, the error is exactly ErrNotFound.
func (tab *Users) FindByName(username string) (*User, error) {
	stmt := tab.style.cmd("SELECT id,", cols, "FROM", tab.table, "WHERE NormalizedUserName = ", tab.style.Param(1))
	key := normalise(username)
	u, err := tab.unpackUser(tab.db.QueryRow(stmt, key))
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("find user: %v", err)
	}
	return u, nil
}

func opts(opt *sql.NullString) string {
	if opt.Valid {
		return opt.String
	}
	return ""
}

// NewUser makes a new user entry in the ASP.NET identity database, returning error ErrExists if the name's already there.
// The NormalizedUserName column is a unique key, so the INSERT will fail if there's a duplicate, avoiding locks or transactions.
func (tab *Users) NewUser(name, email, password string) (*User, error) {
	u, err := tab.FindByName(name)
	if err != nil && err != ErrNotFound {
		return nil, err
	}
	if u != nil {
		//		return nil, ErrExists
	}
	if emptyPassword(password) {
		return nil, ErrNoPassword
	}
	pwd, err := pwdatav3.GenerateFromPassword([]byte(password), pwdatav3.DefaultIter)
	if err != nil {
		return nil, fmt.Errorf("hashing password: %v", err)
	}
	u = &User{
		ID:                 newStamp(),
		UserName:           name,
		NormalizedUserName: normalise(name),
		PasswordHash:       pwdatav3.EncodeToString(pwd),
		Email:              email,
		NormalizedEmail:    normalise(email),
		SecurityStamp:      newStamp(),
		ConcurrencyStamp:   newStamp(),
	}
	stmt := tab.style.cmd("INSERT INTO", tab.table, "(Id, ", cols, ") VALUES (", tab.style.params(1+len(cols)), ")")
	_, err = tab.db.Exec(stmt, u.ID, u.AccessFailedCount, u.ConcurrencyStamp, u.Email, u.EmailConfirmed, u.LockoutEnabled, u.LockoutEnd,
		u.NormalizedEmail, u.NormalizedUserName, u.PasswordHash, u.PhoneNumber, u.PhoneNumberConfirmed, u.SecurityStamp,
		u.TwoFactorEnabled, u.UserName)
	if err != nil {
		if tab.style.IsDuplicate(err) {
			return nil, ErrExists
		}
		return nil, fmt.Errorf("adding new user: %v", err)
	}
	return u, nil
}

// Authenticate, given a user name (email) and password, returns either a user identity or an error.
// If either the authentication fails or the user does not exist, it returns exactly the error ErrInvalidCredentials.
// The AccessFailedCount counts successive authentication failures, but is reset on the next success.
func (tab *Users) Authenticate(name, password string) (*User, error) {
	u, err := tab.FindByName(name)
	if err != nil && err != ErrNotFound {
		return u, err
	}
	if u == nil {
		// set to a dummy value to avoid over-quick return
		u = &User{PasswordHash: emptyHash}
	}
	pwd, err := pwdatav3.DecodeString(u.PasswordHash)
	if err != nil {
		return nil, err
	}
	ok := pwdatav3.CompareHashAndPassword(pwd, []byte(password)) == nil
	tab.accessFailed(u, !ok)
	if !ok {
		return nil, ErrInvalidCredentials
	}
	return u, nil
}

// accessFailed tracks authentication failures but if there's a success, the count is reset.
func (tab *Users) accessFailed(u *User, bad bool) error {
	if bad {
		u.AccessFailedCount++
	} else {
		u.AccessFailedCount = 0
	}
	return tab.Update(u)
}

func newStamp() string {
	return uuid.New().String()
}

func emptyPassword(s string) bool {
	return strings.TrimSpace(s) == ""
}

// ChangePassword tries to update the User's password, rejecting empty ones,
// and if successful, updates both the value and the database.
// Both are left unchanged on failure.
func (tab *Users) ChangePassword(u *User, password string) error {
	if emptyPassword(password) {
		return ErrNoPassword
	}
	pwd, err := pwdatav3.New(password, pwdatav3.DefaultIter)
	if err != nil {
		// it can only be rand.Read failing
		return fmt.Errorf("change password: %v", err)
	}
	text, err := pwd.MarshalText()
	if err != nil {
		// can't happen, but j.i.c.
		return fmt.Errorf("change password: %v", err)
	}
	nu := new(User)
	*nu = *u
	nu.PasswordHash = string(text)
	nu.SecurityStamp = newStamp()
	err = tab.Update(nu)
	if err != nil {
		return err
	}
	u.PasswordHash = nu.PasswordHash
	u.SecurityStamp = nu.SecurityStamp
	return nil
}

// ConfirmEmail marks the user as having confirmed the email address,
// and updates the database entry (which might yield an error).
func (tab *Users) ConfirmEmail(u *User) error {
	u.EmailConfirmed = true
	return tab.Update(u)
}

// Update replaces the existing database values for a given user,
// based on the unique ID. The ConcurrencyStamp value guards
// against a concurrent update or removal of the database record.
// If the check fails, Update returns exactly the error ErrConcurrency,
// and the caller should refetch the value to get the current settings.
// Otherwise, if the operation succeeded, the User value's
// ConcurrencyStamp is updated for use in the next update.
func (tab *Users) Update(u *User) error {
	stamp := newStamp()
	stmt := tab.style.cmd("UPDATE", tab.table, "SET", tab.style.assign(cols), "WHERE Id =", tab.style.Param(len(cols)+1), "AND ConcurrencyStamp =", tab.style.Param(len(cols)+2))
	res, err := tab.db.Exec(stmt,
		u.AccessFailedCount,
		stamp,
		u.Email,
		u.EmailConfirmed,
		u.LockoutEnabled,
		u.LockoutEnd,
		u.NormalizedEmail,
		u.NormalizedUserName,
		u.PasswordHash,
		u.PhoneNumber,
		u.PhoneNumberConfirmed,
		u.SecurityStamp,
		u.TwoFactorEnabled,
		u.UserName,
		u.ID,
		u.ConcurrencyStamp)
	if err != nil {
		return err
	}
	nr, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if nr == 0 {
		// lost race: was updated (hence new concurrency stamp) or deleted by another process
		return ErrConcurrency
	}
	u.ConcurrencyStamp = stamp
	return nil
}

// CheckLockout returns an error iff the given user remains locked out from authentication.
func (tab *Users) CheckLockout(u *User) error {
	if u.LockoutEnabled && u.LockoutEnd != nil && time.Now().Before(*u.LockoutEnd) {
		return ErrLockedOut
	}
	return nil
}

// ResetLockout resets the lockout mark and timeout for a given user.
func (tab *Users) ResetLockout(u *User) error {
	if u.LockoutEnd != nil {
		u.LockoutEnd = nil
		return tab.Update(u)
	}
	return nil
}

// LockOut locks out the user for the given duration.
func (tab *Users) LockOut(u *User, d time.Duration) error {
	nu := new(User)
	*nu = *u
	end := time.Now().Add(d)
	nu.LockoutEnd = &end
	err := tab.Update(nu)
	if err != nil {
		return err
	}
	u.LockoutEnd = &end
	return nil
}

func mustHashPassword(pw string) string {
	pwd, err := pwdatav3.GenerateFromPassword([]byte(pw), pwdatav3.DefaultIter)
	if err != nil {
		panic("aspnetusers: " + err.Error())
	}
	return pwdatav3.EncodeToString(pwd)
}

func (db *Database) params(n int) string {
	var sb strings.Builder
	for i := 0; i < n; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(db.Param(i + 1))
	}
	return sb.String()
}

func (db *Database) assign(cols []string) string {
	var sb strings.Builder
	for i, n := range cols {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(n)
		sb.WriteString("=")
		sb.WriteString(db.Param(i + 1))
	}
	return sb.String()
}

func (db *Database) cmd(verb string, args ...any) string {
	var sb strings.Builder
	sb.WriteString(verb)
	for _, a := range args {
		sb.WriteString(" ")
		switch a := a.(type) {
		case string:
			sb.WriteString(a)
		case []string:
			for j, s := range a {
				if j != 0 {
					sb.WriteString(", ")
				}
				sb.WriteString(s)
			}
		default:
			sb.WriteString(fmt.Sprint(a))
		}
	}
	return sb.String()
}

func normalise(s string) string {
	return strings.ToUpper(s)
}
