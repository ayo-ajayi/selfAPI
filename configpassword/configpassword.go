package configpassword
import (
	"golang.org/x/crypto/bcrypt"
	"fmt"
	"log"
)

func HashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return string(hashedPassword), nil
}

func VerifyPassword(res string, req string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(res), []byte(req))
	check := true
	if err != nil {
		log.Println(err)
		check = false
	}
	return check
}
