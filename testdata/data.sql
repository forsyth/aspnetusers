-- MySQL dump 10.13  Distrib 5.7.25, for Linux (x86_64)
--
-- Host: localhost    Database: aspnet-talkingaloud-eea59002-4459-422d-8f16-38f64fe4442f
-- ------------------------------------------------------
-- Server version	5.7.25-0ubuntu0.18.04.2

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Dumping data for table `aspnetusers`
--

LOCK TABLES aspnetusers WRITE;
/*!40000 ALTER TABLE aspnetusers DISABLE KEYS */;
INSERT INTO aspnetusers (Id, AccessFailedCount, ConcurrencyStamp, Email, EmailConfirmed, LockoutEnabled, LockoutEnd, NormalizedEmail, NormalizedUserName, PasswordHash, PhoneNumber, PhoneNumberConfirmed, SecurityStamp, TwoFactorEnabled, UserName) VALUES
	('02aa6071-58de-46ba-923c-726c7433b78c',0,'281c2486-402b-4baa-9030-b68406ea853f','josephine@example.com',0x00,0x01,NULL,'JOSEPHINE@EXAMPLE.COM','JOSEPHINE@EXAMPLE.COM','AQAAAAEAACcQAAAAEO4k5r1SgFuCYAS8xfu/Mnu5iZUqh+DgSRU4IyJpD+mVo4KdbI1BwiF3KcY1V6AapQ==',NULL,0x00,'7U224TTYHE6VI2LUDQ6LVCWVEJ6UUZ7L',0x00,'josephine@example.com'),
	('3f7ec9a8-443c-4864-9366-b5fa6e5d6930',0,'c37ba7f9-16fd-4cc5-b388-f7a48d1ce0fb','joseph@example.com',0x00,0x01,NULL,'JOSEPH@EXAMPLE.COM','JOSEPH@EXAMPLE.COM','AQAAAAEAACcQAAAAEE0qQFDCDkOmkdayxh4I25EhS8BCNpJoFisWryZ+7NEvYolOW3VvM7NvPShuhLjYig==',NULL,0x00,'YOGKNXEAS46JX2Z4MGI4BADFIQPEIRR4',0x00,'joseph@example.com'),
	('5ec290a6-eb9b-4542-a5ea-70898686cb26',0,'3fcdaba7-c47a-42f8-a856-64815f787d6d','jenny@example.com',0x00,0x01,NULL,'JENNY@EXAMPLE.COM','JENNY@EXAMPLE.COM','AQAAAAEAACcQAAAAEIlFLZh4m/vpVzA1RepTfygQZ5g144Ny0jWN57lgJ9gNnSrUcDGL7ce75I0pCaHJkw==',NULL,0x00,'Q2RFTJFX3YMUTK4LLA7WYE6W42JB2E63',0x00,'jenny@example.com'),
	('ab6c3f50-e783-4ee1-bb7a-c9b227b76d42',0,'75b854aa-4cf3-4003-9baa-631ce4079a0f','frodo@sauron.com',0x00,0x01,NULL,'FRODO@SAURON.COM','FRODO@SAURON.COM','AQAAAAEAACcQAAAAEDwi80lZ8tyhpsTMaSt/bGAhHJn7CT6ia337VgBMVHj4osyPjvt3KjLa6cPCDA9s9g==',NULL,0x00,'6e195f45-00f9-41fb-814a-19adcc2f17b4',0x00,'frodo@sauron.com'),
	('b1f9c65c-5788-4541-a9df-71575538c10e',0,'b776ee20-95fc-48f9-a756-020781b3f567','jake@example.com',0x00,0x01,NULL,'JAKE@EXAMPLE.COM','JAKE@EXAMPLE.COM','AQAAAAEAACcQAAAAEHhGT2mW9BMcWhMNA4lNj80h8OULQyuvqbSR99lZ+GWsuhA2H6HLxcZI8+RhtxV5FA==',NULL,0x00,'XK4KFSOOIGKZJZLJZKUTIZ6HJKD2O3JE',0x00,'jake@example.com');
/*!40000 ALTER TABLE aspnetusers ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2019-04-22 11:20:38