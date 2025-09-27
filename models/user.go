package models

import "gorm.io/gorm"

type User struct {
	gorm.Model
	Name     string `json:"name"`
	Email    string `gorm:"unique" json:"email"`
	Password string `json:"-"`       // jangan ditampilkan saat response JSON
	Provider string `json:"provider"` // local / google
}
