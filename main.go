package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/ayo-ajayi/selfGin/config"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator"
	//"github.com/golang-jwt/jwt/v4"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID         uint64    `bson:"_id"`
	Email      *string   `json:"email" validate:"required,min=2,email"`
	Password   *string   `json:"password" validate:"required,min=5"`
	Created_at time.Time `json:"created_at"`
	Updated_at time.Time `json:"updated_at"`
	//Email          string     `validate:"required,email"`
	//ID         primitive.ObjectID `bson:"_id"`
}

var port, mongo_url, _ = config.Config("", "MONGODB_URL", "ACCESS_SECRET")

func main() {

	client, err := mongo.NewClient(options.Client().ApplyURI(mongo_url))
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	err = client.Connect(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Disconnect(ctx)
	err = client.Ping(ctx, readpref.Primary())
	if err != nil {
		log.Fatal(err)
		return
	}
	log.Println("MongoDB connection successful")

	databases, err := client.ListDatabaseNames(ctx, bson.M{})
	if err != nil {
		log.Fatal(err)
	}
	//log.Println(databases)
	Users := client.Database("selfgin").Collection("Users")
	f, _ := os.Create("gin.log")
	gin.DisableConsoleColor()

	gin.DefaultWriter = io.MultiWriter(f)

	router := gin.Default()
	router.SetTrustedProxies([]string{"192.6.168.201"})

	router.Use(func(c *gin.Context) {
		if c.FullPath() == "" {
			c.Redirect(301, "https://www.google.com/")
		}
		//c.JSON(http.StatusOK, reply)
	})

	router.GET("/databases", func(c *gin.Context) {

		c.JSON(200, gin.H{"databases": databases})
	})

	router.POST("/register", func(c *gin.Context) {

		var users []User
		var user User

		if err := c.BindJSON(&user); err != nil {
			return
		}

		users = append(users, user)

		c.JSON(200, users)

	})

	router.POST("/user", func(c *gin.Context) {
		var input User

		if err := c.BindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		validate := validator.New()

		validationErr := validate.Struct(input)
		if validationErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": validationErr.Error()})
			return
		}

		res, err := Users.InsertOne(ctx, input)
		if err != nil {
			log.Fatal(err)
			return
		}

		c.JSON(http.StatusOK, gin.H{"data": res})
	})

	router.POST("/userregister", func(c *gin.Context) {
		var req User

		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		validate := validator.New()

		validationErr := validate.Struct(req)
		if validationErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": validationErr.Error()})
			return
		}

		hashedPassword, err := HashPassword(*req.Password)
		if err != nil {
			c.JSON(http.StatusInternalServerError, err)
			return
		}

		res, err := Users.InsertOne(ctx, bson.M{
			"email":    req.Email,
			"password": hashedPassword,
		})
		if err != nil {
			log.Fatal(err)
			return
		}

		c.JSON(http.StatusOK, gin.H{"data": res})
	})

	router.POST("/userlogin", func(c *gin.Context) {
		var req User

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
			return
		}
		validate := validator.New()

		validationErr := validate.Struct(req)
		if validationErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": validationErr.Error()})
			return
		}

		res := Users.FindOne(ctx, gin.H{"email": req.Email})

		filterCursor, err := Users.Find(ctx, bson.M{"email": req.Email})
		if err != nil {
			log.Fatal(err)
		}
		var episodesFiltered []bson.M
		if err = filterCursor.All(ctx, &episodesFiltered); err != nil {
			log.Fatal(err)
		}
		fmt.Println(episodesFiltered)




		if res.Err() != nil {
			log.Fatalln(res.Err().Error())
		}

		c.JSON(200, res)

		/*	var seen User
			if seen.Email != input.Email || seen.Password != input.Password {
				c.JSON(http.StatusUnauthorized, "Please provide valid logn details")
				return
			}
			token, err := CreateToken(seen.ID)

			if err != nil {
				c.JSON(http.StatusUnprocessableEntity, err.Error())
				return
			}
			c.JSON(http.StatusOK, token)**/

	})

	router.Run(":" + port)
}

/*func CreateToken(userID uint64) (string, error) {
	var err error
	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["user_id"] = userID
	atClaims["exp"] = time.Now().Add(time.Minute * 15).Unix()
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)

	token, err := at.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}
	return token, nil
}
*/
// learn how to unhash an hashed password to get the real value so as to compare it with the input during a login process.
func HashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return string(hashedPassword), nil
}
