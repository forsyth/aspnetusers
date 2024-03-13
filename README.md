# aspnetuser

-- import "github.com/forsyth/aspnetuser"

Package _aspnetuser_ supports access to a user authentication database previously or concurrently used by ASP.NET Core applications.
It helped me migrate applications from C# to Go, without requiring users to re-register or reset their passwords;
indeed for a time the two services ran side-by-side, sharing the same authentication database.
