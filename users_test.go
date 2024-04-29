package aspnetusers

import (
	"database/sql"
	"errors"
	"os"
	"testing"

	_ "github.com/go-sql-driver/mysql"
)

var names = []string{"frodo@sauron.com", "jake@example.com", "joseph@example.com", "jenny@example.com"}

type testuser struct {
	name string
	b64  string
	pw   string
	err1 string
}

var testusers = []testuser{
	{
		"josephine@example.com",
		"AQAAAAEAACcQAAAAEO4k5r1SgFuCYAS8xfu/Mnu5iZUqh+DgSRU4IyJpD+mVo4KdbI1BwiF3KcY1V6AapQ==",
		"In2Egypt!",
		"password encoding: illegal base64 data at input byte 84",
	},
	{
		"jake@example.com",
		"AQAAAAEAACcQAAAAEHhGT2mW9BMcWhMNA4lNj80h8OULQyuvqbSR99lZ+GWsuhA2H6HLxcZI8+RhtxV5FA==",
		"REdNuIlsAnyejH3",
		"password encoding: illegal base64 data at input byte 84",
	},
}

func TestUser(t *testing.T) {
	dsn := os.Getenv("USERS_DSN")
	if dsn == "" {
		t.Fatalf("must set USERS_DSN to the dsn value for the test database")
	}
	db, err := openDB(dsn)
	if err != nil {
		t.Fatalf("cannot open db: %v", err)
	}
	err = initDB(db)
	if err != nil {
		t.Fatal(err)
	}
	tab := New(db, "aspnetusers", nil)
	t.Run("IdentiyUser", func(t *testing.T) {
		for _, n := range names {
			u, err := tab.FindByName(n)
			if err != nil {
				t.Fatalf("cannot find %v: %v", n, err)
			}
			//fmt.Printf("found %s: %#v\n", n, u)
			nu, err := tab.FindByID(u.ID)
			if err != nil {
				t.Fatalf("cannot find %v by Id %v: %v", n, u.ID, err)
			}
			if *nu != *u && nu.LockoutEnd == nil && u.LockoutEnd == nil {
				t.Fatalf("ByID doesn't match ByName: %v", n)
			}
		}

		u, err := tab.NewUser("jakethedog@example.com", "jakethedog@example.com", "woofy")
		if err != nil {
			t.Errorf("create jake: %v", err)
		}

		// check duplicate create
		ud, err := tab.NewUser("jakethedog@example.com", "jakethedog@example.com", "waffy")
		if err == nil {
			t.Errorf("duplicate jake was allowed: %v\n\t%#v", u, ud)
		} else if !errors.Is(err, ErrExists) {
			t.Errorf("wrong error for duplicate: want %v, got %v", ErrExists, err)
		}

		// check update of several fields
		u.AccessFailedCount = 1
		err = tab.Update(u)
		if err != nil {
			t.Errorf("%s: %v", u.UserName, err)
		}

		// password change
		ostamp := u.SecurityStamp
		err = tab.ChangePassword(u, "hey there!")
		if err != nil {
			t.Errorf("%s: password change failed: %v", u.UserName, err)
		} else {
			t.Logf("%s: security stamp after pw change: before %s after %s", u.UserName, ostamp, u.SecurityStamp)
		}

		// check authentication
		for _, user := range testusers {
			u, err := tab.Authenticate(user.name, user.pw)
			if err != nil {
				t.Errorf("%s: want error nil; got %v", user.name, err)
				continue
			}
			if u.UserName != user.name {
				t.Errorf("%s: mismatched name for Authenticate: %s", user.name, u.UserName)
			}
			if u.PasswordHash != user.b64 {
				t.Errorf("%s: mismatched hashed pw: %v got %v", user.name, user.b64, u.PasswordHash)
			}
			_, err = tab.Authenticate(user.name, "")
			if err == nil {
				t.Errorf("%s: accepted incorrect password", user.name)
			}
			if err != ErrInvalidCredentials {
				t.Errorf("%s: want ErrInvalidCredentials, got %#v", user.name, err)
			}
		}
	})
}

func openDB(dsn string) (*sql.DB, error) {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	if err = db.Ping(); err != nil {
		return nil, err
	}
	return db, nil
}

func initDB(db *sql.DB) error {

	script, err := os.ReadFile("./testdata/setup.sql")
	if err != nil {
		return err
	}
	_, err = db.Exec(string(script))
	if err != nil {
		return err
	}

	script, err = os.ReadFile("./testdata/data.sql")
	if err != nil {
		return err
	}
	_, err = db.Exec(string(script))
	return err
}
