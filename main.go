package main

import (
	"context"
	"fmt"

	pword "github.com/ayo-ajayi/selfAPI/configpassword"
	"github.com/ayo-ajayi/selfAPI/mongodb"
	"github.com/ayo-ajayi/selfGin/config"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator"
	"github.com/golang-jwt/jwt/v4"
	"github.com/twinj/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"

	"io"
	"log"
	"net/http"
	"os"
	"time"
)

type User struct {
	Email      *string            `json:"email" validate:"required,min=2,email"`
	Password   *string            `json:"password" validate:"required,min=5"`
	Created_at time.Time          `json:"created_at"`
	Updated_at time.Time          `json:"updated_at"`
	ID         primitive.ObjectID `bson:"_id,omitempty" json:"id"`
}

type TokenDetails struct {
	AccessToken  string `json:"accesstoken"`
	RefreshToken string `json:"refreshtoken"`
	AccessUuid   string `json:"accessuuid"`
	RefreshUuid  string `json:"refreshuuid"`
	AtExpires    int64  `json:"atexpires"`
	RtExpires    int64  `json:"rtexpires"`
}
type Save struct {
	Email       string             `json:"email"`
	UserID      primitive.ObjectID `json:"user_id"`
	AccessToken string             `json:"accesstoken"`
}
type Todo struct {
	Note   string             `json:"note"`
	UserID primitive.ObjectID `bson:"user_id,omitempty" json:"user_id"`
	//TaskId primitive.ObjectID `json:"taskid"`
}

var (
	port, rSecret, aSecret = config.Config("", "REFRESH_SECRET", "ACCESS_SECRET")
	Tokens                 *mongo.Collection
	Users                  *mongo.Collection
	Todos                  *mongo.Collection
)
var err error

func main() {

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	Tokens, Users, Todos = mongodb.Init()
	f, _ := os.Create("gin.log")
	gin.DisableConsoleColor()
	gin.DefaultWriter = io.MultiWriter(f)
	router := gin.Default()
	router.SetTrustedProxies([]string{"192.6.168.201"})

	router.POST("/register", func(c *gin.Context) {
		var users []User
		var user User
		if err := c.BindJSON(&user); err != nil {
			return
		}
		users = append(users, user)
		c.JSON(200, users)

	})

	router.POST("/signup", func(c *gin.Context) {
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
		count, err := Users.CountDocuments(ctx, bson.M{"email": req.Email})
		if count != 0 {
			c.JSON(http.StatusUnauthorized, "User already exists")
			return
		}
		if err != nil {
			log.Fatal(err)
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
		td, err := CreateToken(res.InsertedID.(primitive.ObjectID))
		if err != nil {
			log.Fatal(err)
			return
		}
		c.Header("auth", td.AccessToken)

		save := Save{
			Email:       *req.Email,
			UserID:      res.InsertedID.(primitive.ObjectID),
			AccessToken: td.AccessToken,
		}

		r, err := Tokens.InsertOne(context.TODO(), save)
		if err != nil {
			c.JSON(400, err)
		}

		c.JSON(http.StatusOK, gin.H{"data": r})

	})

	router.POST("/login", func(c *gin.Context) {
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

		c.Header("auth", token.AccessToken)
		c.JSON(http.StatusOK, gin.H{"data": res})

	})
	router.POST("/todo", NewTodo)
	router.GET("/todo", GetTodo)
	router.GET("/todo/:id", GetTodoByID)
	router.Run(":" + port)

}

//Todo user_id
//Tokens userid

func GetTodoByID(c *gin.Context) {
	users := VerifyToken(c)
	id := c.Param("id")
	count, err := Todos.CountDocuments(context.TODO(), bson.M{"_id": id, "user_id": users["InsertedID"]})
	if count == 0 {
		c.JSON(404, "Document doesn't exist")
		return
	}
	if err != nil {
		log.Fatal(err)
	}
	var res bson.M
	err = Todos.FindOne(context.TODO(), bson.M{"_id": id, "user_id": users["InsertedID"]}).Decode(&res)
	if err != nil {

		if err == mongo.ErrNoDocuments {
			return
		}
		log.Fatal(err)
	}
	c.JSON(200, res)

}

func GetTodo(c *gin.Context) {
	users := VerifyToken(c)

	res, err := Tokens.Find(context.TODO(), bson.M{"userid": users["InsertedID"]})

	if err != nil {

		if err == mongo.ErrNoDocuments {
			return
		}
		log.Fatal(err)
	}
	c.JSON(200, res)
}

func NewTodo(c *gin.Context) {
	users := VerifyToken(c)
	var req Todo
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
	res, err := Todos.InsertOne(context.TODO(),
		bson.M{

			"note":       req.Note,
			"user_id":    users["_id"],
			"created_at": time.Now(),
		},
	)

	if err != nil {
		c.JSON(400, err)
	}
	c.JSON(200, res)
}

func VerifyToken(c *gin.Context) bson.M {
	tokenString := c.GetHeader("auth")
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {

		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("ACCESS_SECRET")), nil
	})
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
	}

	var tokens bson.M
	err = Tokens.FindOne(context.TODO(), bson.M{"accesstoken": token.Raw}).Decode(&tokens)
	if err != nil {

		if err == mongo.ErrNoDocuments {
			c.JSON(400, "not found")
		}
		log.Fatal(err)
	}

	var users bson.M
	err = Users.FindOne(context.TODO(), bson.M{"_id": tokens["userid"]}).Decode(&users)
	if err != nil {

		if err == mongo.ErrNoDocuments {
			c.JSON(400, "not found")
		}
		log.Fatal(err)
	}
	return users
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

//c.Request.Body = res
//res.AccessUuid
//decode the id from the accessuuid
