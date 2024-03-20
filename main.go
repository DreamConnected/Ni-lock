package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"embed"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/kardianos/service"
)

//go:embed src/ni-unlock.png src/ni-lock.png
var files embed.FS

const (
	privateKeyFile = "private.pem"
	publicKeyFile  = "public.pem"
	yellow         = "\033[33m%s\033[0m"
	red            = "\033[31m%s\033[0m"
	green          = "\033[32m%s\033[0m"
)

func main() {
	prog := &program{}
	s, err := service.New(prog, serviceConfig)
	if err != nil {
		log.Fatal(err)
	}

	var errlog error
	logger, errlog = s.Logger(nil)
	if errlog != nil {
		log.Fatal(err)
	}

	if len(os.Args) > 1 {
		command := os.Args[1]
		switch command {
		case "init":
			err := initialize()
			if err != nil {
				errMsg := "[ ERRO ] Initialization failed:" + err.Error() + "\n"
				fmt.Printf(red, errMsg)
			} else {
				doneMsg := "\n[ INFO ] Initialization successful.\n"
				fmt.Printf(green, doneMsg)
			}
		case "encrypt":
			if len(os.Args) < 3 {
				fmt.Println("")
				fmt.Println("Usage: ni-lock encrypt [input Directory] [output Directory (optional)]")
				fmt.Println("")
				return
			}
			inputDir := os.Args[2]
			var outputDir string
			if len(os.Args) > 3 {
				outputDir = os.Args[3]
			}
			err := enProcessFilesInDirectory(inputDir, func(file string) error {
				return encryptFile(file, outputDir)
			})
			if err != nil {
				errMsg := "\n[ ERRO ] Encryption failed: " + err.Error()
				fmt.Printf(red, errMsg)
			} else {
				flagFile := filepath.Join(inputDir, "decrypted.flag")
				if _, err := os.Stat(flagFile); err == nil {
					err := os.Remove(flagFile)
					if err != nil {
						doneMsg := "\n[ INFO ] Running on non removable disk, skipping flags."
						fmt.Printf(green, doneMsg)
						return
					}
					doneMsg := "\n[ INFO ] The decryption flag was successfully removed, and your drive is protected."
					fmt.Printf(green, doneMsg)
				}
				doneMsg := "\n[ INFO ] Encryption successful."
				fmt.Printf(green, doneMsg)
			}
		case "decrypt":
			if len(os.Args) < 3 {
				fmt.Println("")
				fmt.Println("Usage: ni-lock decrypt [input Directory] [output Directory (optional)]")
				fmt.Println("")
				return
			}
			inputDir := os.Args[2]
			var outputDir string
			if len(os.Args) > 3 {
				outputDir = os.Args[3]
			}
			err := deProcessFilesInDirectory(inputDir, func(file string) error {
				return decryptFile(file, privateKeyFile, outputDir)
			})
			if err != nil {
				errMsg := "\n[ ERRO ] Decryption failed!\n" + err.Error()
				fmt.Printf(red, errMsg)
			} else {
				err := cleanAesKey(inputDir)
				if err != nil {
					errMsg := "\n[ ERRO ] Failed to clean AES key file.\n" + err.Error()
					fmt.Printf(red, errMsg)
				}
				doneMsg1 := "\n[ INFO ] The AES key has been successfully cleared "
				fmt.Printf(green, doneMsg1)
				doneMsg := "\n[ INFO ] Decryption successful."
				fmt.Printf(green, doneMsg)
			}
		case "install":
			err = s.Install()
			if err != nil {
				log.Fatal(err)
			}
			doneMsg1 := "\n[ INFO ] Daemon registration successful."
			fmt.Printf(green, doneMsg1)
			s.Start()
		case "remove":
			s.Stop()
			err = s.Uninstall()
			if err != nil {
				log.Fatal(err)
			}
			if err != nil {
				log.Fatal(err)
			}
			doneMsg1 := "\n[ INFO ] Successfully removed the daemon."
			fmt.Printf(green, doneMsg1)
		case "auto":
			if isRunningOnRemovableDisk() {
				fmt.Println("\n[ INFO ] Starting auto Decryption ...")
				executable, err := os.Executable()
				if err != nil {
					fmt.Println(err)
					return
				}

				var outputDir string
				executableDir := filepath.Dir(executable)
				inputDir := filepath.Join(executableDir, "..")
				err = deProcessFilesInDirectory(inputDir, func(file string) error {
					return decryptFile(file, privateKeyFile, outputDir)
				})

				if err != nil {
					fmt.Println("\n[ ERRO ] Auto Decryption failed:", err)
				} else {
					fmt.Println("\n[ INFO ] Auto Decryption done.")
				}
			} else {
				errMsg := "\n[ ERRO ] Autorun cannot run on non removable disks.\n"
				fmt.Printf(red, errMsg)
			}
		default:
			fmt.Println("ni-lock is a tool for protecting your files.")
			fmt.Println("")
			fmt.Println("Usage:")
			fmt.Println("")
			fmt.Println("	ni-lock <command> [arguments]")
			fmt.Println("")
			fmt.Println("The commands are:")
			fmt.Println("")
			fmt.Println("	init		Generate RSA key pairs")
			fmt.Println("	install		Automatically decrypt when inserting a removable disk")
			fmt.Println("	remove		Remove the automatic decryption daemon")
			fmt.Println("	auto		Suitable for Win7 and below, with complete Autorun.inf support")
			fmt.Println("	encrypt		Encrypt files from directory")
			fmt.Println("	decrypt		Decrypt files from directory")
			fmt.Println("")
			return
		}
	} else {
		err = s.Run()
		if err != nil {
			logger.Error(err)
		}
	}
}

func initialize() error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}

	fmt.Println("\n[ INFO ] Generating the RSA PrivateKey ...")

	// 生成私钥文件
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	privateKeyFile, err := os.Create(privateKeyFile)
	if err != nil {
		return err
	}
	defer privateKeyFile.Close()

	err = pem.Encode(privateKeyFile, privateKeyPEM)
	if err != nil {
		return err
	}

	fmt.Println("\n[ INFO ] Generating the RSA PublicKey ...")

	// 生成公钥文件
	publicKey := &privateKey.PublicKey
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}
	publicKeyPEM := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	publicKeyFile, err := os.Create(publicKeyFile)
	if err != nil {
		return err
	}
	defer publicKeyFile.Close()

	err = pem.Encode(publicKeyFile, publicKeyPEM)
	if err != nil {
		return err
	}

	doneMsg := "\n[ INFO ] Initialization completed, Done!"
	fmt.Printf(green, doneMsg)
	warnMsg := "\n[ WARN ] 保管好生成的 private.pem 私钥证书和 public.pem 公钥证书\n如果掉了必须生成新的证书对！！！且新的证书对无法解密之前加密的任何文件！！！\n"
	fmt.Printf(yellow, warnMsg)

	return nil
}

func encryptFile(inputFile string, outputDir string) error {
	fileName := filepath.Base(inputFile)
	skipFiles := []string{"ni-lock.exe", "autorun.inf", "private.pem", "ni-lock.png", "public.pem"}
	if strings.HasSuffix(inputFile, ".ni-lock") || strings.HasSuffix(inputFile, ".ni-lock-aes") {
		warnMsg := "\n[ WARN ] Skip file: " + inputFile + "\n"
		fmt.Printf(yellow, warnMsg)
		return nil
	}

	for _, skipFile := range skipFiles {
		if fileName == skipFile {
			warnMsg := "\n[ WARN ] Skip file: " + inputFile + "\n"
			fmt.Printf(yellow, warnMsg)
			return nil
		}
	}

	outputFilePathLock := filepath.Join(outputDir, fileName+".ni-lock")
	if _, err := os.Stat(outputFilePathLock); err == nil {
		warnMsg := "\n[ WARN ] Skip file ( already encrypted ): " + inputFile + "\n"
		fmt.Printf("%s", warnMsg)
		return nil
	}

	outputFilePathAES := filepath.Join(outputDir, fileName+".ni-lock-aes")
	if _, err := os.Stat(outputFilePathAES); err == nil {
		warnMsg := "\n[ WARN ] Skip file ( already encrypted with AES ): " + inputFile + "\n"
		fmt.Printf("%s", warnMsg)
		return nil
	}

	publicKeyData, err := os.ReadFile(publicKeyFile)
	if err != nil {
		return err
	}

	block, _ := pem.Decode(publicKeyData)
	if block == nil {
		return errors.New("failed to decode public key")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}

	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("invalid public key type")
	}

	Data, err := os.Open(inputFile)
	if err != nil {
		return err
	}
	defer Data.Close()

	inputData, err := io.ReadAll(Data)
	if err != nil {
		return err
	}

	err = Data.Close()
	if err != nil {
		return err
	}

	aesEncryptedData, key, err := aesEncrypt(inputData)
	if err != nil {
		return err
	}

	encryptedKey, err := rsaEncrypt(key, rsaPublicKey)
	if err != nil {
		return err
	}

	outputFile := inputFile + ".ni-lock"
	if outputDir != "" {
		outputFile = filepath.Join(outputDir, filepath.Base(inputFile)+".ni-lock")
	}

	outputKeyFile := inputFile + ".ni-lock-aes"
	if outputDir != "" {
		outputKeyFile = filepath.Join(outputDir, filepath.Base(inputFile)+".ni-lock-aes")
	}

	err = os.WriteFile(outputFile, aesEncryptedData, 0644)
	if err != nil {
		return err
	}

	err = os.WriteFile(outputKeyFile, encryptedKey, 0644)
	if err != nil {
		return err
	}

	err = os.Remove(inputFile)
	if err != nil {
		return err
	}

	err = os.MkdirAll("ni-lock", 0755)
	if err != nil {
		return err
	}

	nilockPNGData, err := files.ReadFile("src/ni-lock.png")
	if err != nil {
		return err
	}

	err = os.WriteFile("ni-lock/ni-lock.png", nilockPNGData, 0644)
	if err != nil {
		return err
	}

	return nil
}

func decryptFile(inputFile string, privateKeyFile string, outputDir string) error {
	fileName := filepath.Base(inputFile)
	skipFiles := []string{"ni-lock.exe", "autorun.inf", "private.pem", "ni-lock.png", "public.pem"}
	aesFileName := fileName + "-aes"
	aesFilePath := filepath.Join(filepath.Dir(inputFile), aesFileName)

	if strings.HasSuffix(fileName, ".ni-lock") {
		// 判断是否存在对应的 .ni-lock-aes 文件
		if _, err := os.Stat(aesFilePath); os.IsNotExist(err) {
			erroMsg := "\n[ ERRO ] AES key missing for file: " + inputFile
			fmt.Printf(red, erroMsg)
			return err
		}
	} else {
		warnMsg := "\n[ WARN ] Skip file (Protected): " + inputFile + "\n"
		fmt.Printf(yellow, warnMsg)
		return nil
	}

	for _, skipFile := range skipFiles {
		if fileName == skipFile {
			warnMsg := "\n[ WARN ] Skip file ( Self protection ): " + inputFile + "\n"
			fmt.Printf(yellow, warnMsg)
			return nil
		}
	}

	privateKeyData, err := os.ReadFile(privateKeyFile)
	if err != nil {
		return fmt.Errorf("failed to read private key file: %v", err)
	}

	block, _ := pem.Decode(privateKeyData)
	if block == nil {
		return errors.New("failed to decode private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}

	preEncryptData, err := os.ReadFile(inputFile)
	if err != nil {
		return err
	}

	outputData, err := os.Open(inputFile + "-aes")
	if err != nil {
		return err
	}

	aesEncryptKey, err := io.ReadAll(outputData)
	if err != nil {
		outputData.Close()
		return err
	}
	outputData.Close()

	aesDecryptKey, err := rsaDecrypt(aesEncryptKey, privateKey)
	if err != nil {
		return err
	}

	decryptedData, err := aesDecrypt(preEncryptData, aesDecryptKey)
	if err != nil {
		return err
	}

	outputFile := strings.TrimSuffix(inputFile, ".ni-lock")
	if outputDir != "" {
		outputFile = filepath.Join(outputDir, filepath.Base(strings.TrimSuffix(inputFile, ".ni-lock")))
	}

	err = os.WriteFile(outputFile, decryptedData, 0)
	if err != nil {
		return err
	}

	if err := os.Remove(inputFile); err != nil {
		return err
	}

	err = os.MkdirAll("ni-lock", 0755)
	if err != nil {
		return err
	}

	niUnlockPNGData, err := files.ReadFile("src/ni-unlock.png")
	if err != nil {
		return err
	}

	err = os.WriteFile("ni-lock/ni-lock.png", niUnlockPNGData, 0644)
	if err != nil {
		return err
	}

	return nil
}
