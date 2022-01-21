package main

import (
	"context"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/ayo-ajayi/selfGin/config"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator"

	pword "github.com/ayo-ajayi/selfAPI/configpassword"
	"github.com/golang-jwt/jwt/v4"
	"github.com/twinj/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

type User struct {
	Email      *string            `json:"email" validate:"required,min=2,email"`
	Password   *string            `json:"password" validate:"required,min=5"`
	Created_at time.Time          `json:"created_at"`
	Updated_at time.Time          `json:"updated_at"`
	ID         primitive.ObjectID `bson:"_id"`
}

type TokenDetails struct {
	AccessToken  string
	RefreshToken string
	AccessUuid   string
	RefreshUuid  string
	AtExpires    int64
	RtExpires    int64
}

var port, mongo_url, aSecret = config.Config("", "MONGODB_URL", "ACCESS_SECRET")
var _, _, rSecret = config.Config("", "", "REFRESH_SECRET")

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

		hashedPassword, err := pword.HashPassword(*req.Password)
		if err != nil {
			c.JSON(http.StatusInternalServerError, err)
			return
		}

		res, err := Users.InsertOne(ctx, bson.M{
			"email":      req.Email,
			"password":   hashedPassword,
			"created_at": time.Now(),
		})
		if err != nil {
			log.Fatal(err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"data": res})
	})

	router.POST("/userlogin", func(c *gin.Context) {
		var req User
		var res User
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

		if err = Users.FindOne(ctx, bson.M{"email": req.Email}).Decode(&res); err != nil {
			log.Fatal(err)
		}
		verify := pword.VerifyPassword(*res.Password, *req.Password)

		if !verify {
			c.JSON(http.StatusUnauthorized, "Please provide valid login details")
			return
		}
		token, err := CreateToken(res.ID)

		if err != nil {
			c.JSON(http.StatusUnprocessableEntity, err.Error())
			return
		}
		c.JSON(http.StatusOK, token)
	})

	router.Run(":" + port)

}

func CreateToken(userID primitive.ObjectID) (*TokenDetails, error) {
	var err error
	td := &TokenDetails{
		AccessUuid:  uuid.NewV4().String(),
		RefreshUuid: uuid.NewV4().String(),
		AtExpires:   time.Now().Add(time.Minute * 15).Unix(),
		RtExpires:   time.Now().Add(time.Hour * 24 * 7).Unix(),
	}

	//access token
	accessTokenClaims := jwt.MapClaims{
		"authorized":  true,
		"access_uuid": td.AccessUuid,
		"user_id":     userID,
		"exp":         td.AtExpires,
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessTokenClaims)
	td.AccessToken, err = accessToken.SignedString([]byte(aSecret))
	if err != nil {
		return nil, err
	}

	//refresh token
	refreshTokenClaims := jwt.MapClaims{
		"refresh_uuid": td.RefreshUuid,
		"user_id":      userID,
		"exp":          td.AtExpires,
	}
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshTokenClaims)
	td.RefreshToken, err = refreshToken.SignedString([]byte(rSecret))
	if err != nil {
		return nil, err
	}
	return td, nil
}
