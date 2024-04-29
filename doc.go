// Package aspnetusers implements password handling compatible with Microsoft's ASP.NET Core, including
// bitwise compatibility of values in the user database "aspnetusers".
// It is useful when switching from C# to Go for the server side of an application,
// avoiding the need to reset passwords when switching,
// and it allows the two servers to run alongside each other, sharing the same
// authentication database.
//
// User holds the authentication values ASP.NET keeps for its users; there is some historic redundancy.
// It corresponds to IdentityUser (and its derived class ApplicationUser) in ASP.NET.
// User has a primary key ID, a unique key UserName and an Email key (not necessarily unique).
// In modern applications, the UserName will usually be an email address, but might still differ from Email.
// Only the latter is confirmed though, so allowing them to differ might be unwise.
// Add new users with NewUser, find them with FindByID or FindByName (the user name) and Update
// as required.
//
// The MySQL definition of table 'aspnetusers' can act
// as a guide to other SQL and NoSQL implementations:
//
//	DROP TABLE IF EXISTS `aspnetusers`;
//	CREATE TABLE `aspnetusers` (
//	  `Id` varchar(127) NOT NULL,
//	  `AccessFailedCount` int(11) NOT NULL,
//	  `ConcurrencyStamp` longtext,
//	  `Email` varchar(256) DEFAULT NULL,
//	  `EmailConfirmed` bit(1) NOT NULL,
//	  `LockoutEnabled` bit(1) NOT NULL,
//	  `LockoutEnd` datetime(6) DEFAULT NULL,
//	  `NormalizedEmail` varchar(256) DEFAULT NULL,
//	  `NormalizedUserName` varchar(256) DEFAULT NULL,
//	  `PasswordHash` longtext,
//	  `PhoneNumber` longtext,
//	  `PhoneNumberConfirmed` bit(1) NOT NULL,
//	  `SecurityStamp` longtext,
//	  `TwoFactorEnabled` bit(1) NOT NULL,
//	  `UserName` varchar(256) DEFAULT NULL,
//	  PRIMARY KEY (`Id`),
//	  KEY `EmailIndex` (`NormalizedEmail`),
//	  UNIQUE KEY `UserNameIndex` (`NormalizedUserName`)
//	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
//
// Note that MySQL uses bit(1) not BOOLEAN.
package aspnetusers
