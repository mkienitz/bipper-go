package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/scrypt"
)

var schema = `
CREATE TABLE IF NOT EXISTS blobs (
    passphrase_hash BLOB NOT NULL PRIMARY KEY,
    filename TEXT NOT NULL,
    content_nonce BLOB NOT NULL,
    filename_nonce BLOB NOT NULL
)
`

// Look my cool comment
func createStoreDirectory() {
	storePath := "store/"
	if _, err := os.Stat(storePath); errors.Is(err, os.ErrNotExist) {
		err := os.Mkdir(storePath, os.ModePerm)
		if err != nil {
			log.Fatal(err)
		}
	}
}

func mnemonicToKeys(mnemonic string) ([]byte, []byte, []byte) {
	salt := []byte{0xd6, 0xef, 0x7d, 0x0c, 0xc9, 0x97, 0x4b, 0xe1}
	derivedMaterial, _ := scrypt.Key([]byte(mnemonic), salt, 1<<15, 8, 1, 96)
	passphraseHash := derivedMaterial[:32]
	contentKey := derivedMaterial[32:64]
	filenameKey := derivedMaterial[64:]
	return passphraseHash, contentKey, filenameKey
}

func encrypt(plaintext []byte, key []byte) ([]byte, []byte) {
	block, _ := aes.NewCipher(key)
	aesgcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, aesgcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce
}

func decrypt(ciphertext []byte, key []byte, nonce []byte) []byte {
	block, _ := aes.NewCipher(key)
	aesgcm, _ := cipher.NewGCM(block)
	plaintext, _ := aesgcm.Open(nil, nonce, ciphertext, nil)
	return plaintext
}

type StoreMetadata struct {
	PassphraseHash []byte `db:"passphrase_hash"`
	Filename       []byte `db:"filename"`
	ContentNonce   []byte `db:"content_nonce"`
	FilenameNonce  []byte `db:"filename_nonce"`
}

func storeFile(c *gin.Context, fileHeader *multipart.FileHeader, db *sqlx.DB) string {
	// Open and read file
	file, err := fileHeader.Open()
	if err != nil {
		c.AbortWithError(400, err)
	}
	defer file.Close()

	filename := fileHeader.Filename
	content, err := io.ReadAll(file)
	if err != nil {
		c.AbortWithError(500, err)
	}
	// Generate BIP39 phrase
	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		c.AbortWithError(500, err)
	}
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		c.AbortWithError(500, err)
	}
	// Derive key material from passphrase
	passphraseHash, contentKey, filenameKey := mnemonicToKeys(mnemonic)
	// Encrypt
	contentBlob, contentNonce := encrypt(content, contentKey)
	filenameCipher, filenameNonce := encrypt([]byte(filename), filenameKey)
	metadata := StoreMetadata{
		passphraseHash,
		filenameCipher,
		contentNonce,
		filenameNonce,
	}
	// Store results
	tx, err := db.Beginx()
	if err != nil {
		c.AbortWithError(500, err)
	}
	_, err = tx.NamedExec(`INSERT INTO blobs (passphrase_hash, filename, content_nonce, filename_nonce)
		VALUES (:passphrase_hash, :filename, :content_nonce, :filename_nonce)`, metadata)
	if err != nil {
		c.AbortWithError(500, err)
	}
	if err := os.WriteFile(fmt.Sprintf("store/%x", filenameCipher), contentBlob, 0644); err != nil {
		c.AbortWithError(500, err)
	}
	if err := tx.Commit(); err != nil {
		c.AbortWithError(500, err)
	}
	return mnemonic
}

func retrieveFile(c *gin.Context, mnemonic string, db *sqlx.DB) (string, []byte) {
	// Derive key material from passphrase
	passphraseHash, contentKey, filenameKey := mnemonicToKeys(mnemonic)
	// Check database
	var metadata StoreMetadata
	if err := db.Get(&metadata, `SELECT * FROM blobs WHERE passphrase_hash=:passphrase_hash`, passphraseHash); err != nil {
		c.AbortWithError(500, err)
	}
	// Restore file
	ciphertext, err := os.ReadFile(fmt.Sprintf("store/%x", metadata.Filename))
	if err != nil {
		c.AbortWithError(500, err)
	}
	content := decrypt(ciphertext, contentKey, metadata.ContentNonce)
	filename := decrypt(metadata.Filename, filenameKey, metadata.FilenameNonce)
	return string(filename), content
}

func main() {
	databaseFile := flag.String("database", "bipper.sqlite", "Path to SQLite database file")
	flag.Parse()

	createStoreDirectory()
	db, err := sqlx.Open("sqlite3", *databaseFile)
	defer db.Close()
	if err != nil {
		log.Fatal("Could not open database schema")
	}
	if _, err := db.Exec(schema); err != nil {
		log.Fatal("Could not create database schema")
	}

	router := gin.Default()
	router.POST("/store", func(c *gin.Context) {
		fileHeader, err := c.FormFile("file")
		if err != nil {
			c.AbortWithError(400, err)
		}
		mnemonic := storeFile(c, fileHeader, db)
		c.JSON(http.StatusOK, gin.H{
			"passphrase": mnemonic,
		})
	})
	router.POST("/retrieve", func(c *gin.Context) {
		type Payload struct {
			Passphrase string `json:"passphrase" binding:"required"`
		}
		var payload Payload
		if err := c.BindJSON(&payload); err != nil {
			c.AbortWithError(400, err)
		}
		filename, content := retrieveFile(c, payload.Passphrase, db)
		c.Header("Content-Disposition", "attachment; filename="+filename)
		c.Data(http.StatusOK, "application/octet-stream", content)
	})
	router.Run()
}
