// +build vault

package cmd

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/go-acme/lego/certcrypto"
	"github.com/go-acme/lego/lego"
	"github.com/go-acme/lego/log"
	"github.com/go-acme/lego/registration"
	"github.com/urfave/cli"
)

const (
	baseAccountsRootFolderName = "accounts"
	baseKeysFolderName         = "keys"
	accountFileName            = "account.json"
)

// AccountsStorage A storage for account data.
//
// rootPath:
//
//     ./.lego/accounts/
//          │      └── root accounts directory
//          └── "path" option
//
// rootUserPath:
//
//     ./.lego/accounts/localhost_14000/hubert@hubert.com/
//          │      │             │             └── userID ("email" option)
//          │      │             └── CA server ("server" option)
//          │      └── root accounts directory
//          └── "path" option
//
// keysPath:
//
//     ./.lego/accounts/localhost_14000/hubert@hubert.com/keys/
//          │      │             │             │           └── root keys directory
//          │      │             │             └── userID ("email" option)
//          │      │             └── CA server ("server" option)
//          │      └── root accounts directory
//          └── "path" option
//
// accountFilePath:
//
//     ./.lego/accounts/localhost_14000/hubert@hubert.com/account.json
//          │      │             │             │             └── account file
//          │      │             │             └── userID ("email" option)
//          │      │             └── CA server ("server" option)
//          │      └── root accounts directory
//          └── "path" option
//
type AccountsStorage struct {
	userID          string
	ctx             *cli.Context

	Client          *vaultClient
}

// NewAccountsStorage Creates a new AccountsStorage.
func NewAccountsStorage(ctx *cli.Context) *AccountsStorage {
	// TODO: move to account struct? Currently MUST pass email.
	email := getEmail(ctx)

	return &AccountsStorage{
		userID:          email,
		ctx:             ctx,

		Client: NewVaultClient(""),
	}
}

func (s *AccountsStorage) ExistsAccountFilePath() bool {
	c, err := s.Client.Get()
	if err != nil {
		log.Fatalf("vault: client: %s", err)
	}

	resp, err := c.Logical().Read(
		fmt.Sprintf("secret/data/fabio/account/%s", s.userID),
	)
	if err != nil || resp == nil {
		return false
	}

	return true
}

func (s *AccountsStorage) GetRootPath() string {
	return ""
}

func (s *AccountsStorage) GetRootUserPath() string {
	return ""
}

func (s *AccountsStorage) GetUserID() string {
	return s.userID
}

func (s *AccountsStorage) Save(account *Account) error {
	c, err := s.Client.Get()
	if err != nil {
		log.Fatalf("vault: client: %s", err)
	}

	jsonBytes, err := json.MarshalIndent(account, "", "\t")
	if err != nil {
		return err
	}

	_, err = c.Logical().Write(
		fmt.Sprintf("secret/data/fabio/account/%s", account.Email),
		map[string]interface{}{
			"data": map[string]interface{}{
				"data": string(jsonBytes),
			},
		},
	)

	return err
}

func (s *AccountsStorage) LoadAccount(privateKey crypto.PrivateKey) *Account {
	c, err := s.Client.Get()
	if err != nil {
		log.Fatalf("vault: client: %s", err)
	}

	resp, err := c.Logical().Read(
		fmt.Sprintf("secret/data/fabio/account/%s", s.userID),
	)
	if err != nil {
		log.Fatalf("Error while loading account %s\n\t%v", s.userID, err)
	}

	var account Account
	d := resp.Data["data"].(map[string]interface{})
	err = json.Unmarshal([]byte(d["data"].(string)), &account)
	if err != nil {
		log.Fatalf("Could not parse file for account %s -> %v", s.userID, err)
	}

	account.key = privateKey

	if account.Registration == nil || account.Registration.Body.Status == "" {
		reg, err := tryRecoverRegistration(s.ctx, privateKey)
		if err != nil {
			log.Fatalf("Could not load account for %s. Registration is nil -> %#v", s.userID, err)
		}

		account.Registration = reg
		err = s.Save(&account)
		if err != nil {
			log.Fatalf("Could not save account for %s. Registration is nil -> %#v", s.userID, err)
		}
	}

	return &account
}

func (s *AccountsStorage) GetPrivateKey(keyType certcrypto.KeyType) crypto.PrivateKey {
	c, err := s.Client.Get()
	if err != nil {
		log.Fatalf("vault: client: %s", err)
	}

	resp, err := c.Logical().Read(
		fmt.Sprintf("secret/data/fabio/private_key/%s", s.userID),
	)
	if err != nil {
		log.Fatalf("No key found for account %s. Generating a %s key., err: %v", s.userID, keyType, err)
	}

	if resp == nil {
		log.Printf("No key found for account %s. Generating a %s key.", s.userID, keyType)

		privateKey, err := certcrypto.GeneratePrivateKey(keyType)
		if err != nil {
			log.Fatalf("Could not generate RSA private account key for account %s: %v", s.userID, err)
		}

		pemKey := certcrypto.PEMBlock(privateKey)
		_, err = c.Logical().Write(
			fmt.Sprintf("secret/data/fabio/private_key/%s", s.userID),
			map[string]interface{}{
				"data": map[string]interface{}{
					"data": string(pem.EncodeToMemory(pemKey)),
				},
			},
		)
		if err != nil {
			log.Fatalf("Could not write private account key for account %s: %v", s.userID, err)
		}

		return privateKey
	}

	d := resp.Data["data"].(map[string]interface{})
	privateKey, err := loadPrivateKey([]byte(d["data"].(string)))
	if err != nil {
		log.Fatalf("Could not load RSA private key from file %s: %v", s.userID, err)
	}

	return privateKey
}


func loadPrivateKey(keyBytes []byte) (crypto.PrivateKey, error) {
	keyBlock, _ := pem.Decode(keyBytes)

	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(keyBlock.Bytes)
	}

	return nil, errors.New("unknown private key type")
}

func tryRecoverRegistration(ctx *cli.Context, privateKey crypto.PrivateKey) (*registration.Resource, error) {
	// couldn't load account but got a key. Try to look the account up.
	config := lego.NewConfig(&Account{key: privateKey})
	config.CADirURL = ctx.GlobalString("server")
	config.UserAgent = fmt.Sprintf("lego-cli/%s", ctx.App.Version)

	client, err := lego.NewClient(config)
	if err != nil {
		return nil, err
	}

	reg, err := client.Registration.ResolveAccountByKey()
	if err != nil {
		return nil, err
	}
	return reg, nil
}
