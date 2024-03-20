package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func enProcessFilesInDirectory(directory string, processFunc func(string) error) error {
	var fileCount int
	var totalFileCount int

	// 计算目录中的文件总数
	err := filepath.Walk(directory, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		if !info.IsDir() && info.Mode().IsRegular() { // 判断是否为普通文件
			totalFileCount++
		}
		return nil
	})

	if err != nil {
		return err
	}

	// 遍历目录并处理文件
	var processErr error
	err = filepath.Walk(directory, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		if !info.IsDir() && info.Mode().IsRegular() { // 判断是否为普通文件
			fileName := filepath.Base(path)

			skipErr := enSkipFileCheck(path)
			if skipErr != nil {
				fmt.Println(skipErr)
				return nil
			}

			fileCount++
			fmt.Printf("\rProcessing file %d: %s", fileCount, fileName)
			processErr = processFunc(path)
			if processErr != nil {
				fmt.Printf("\nError processing file: %v", processErr)
				return processErr // 如果处理文件出错，直接返回错误，停止继续处理其他文件
			}
			fmt.Printf("\rProgress: %.2f%%", float64(fileCount)/float64(totalFileCount)*100)
		}
		return nil
	})

	return err
}

func enSkipFileCheck(inputFile string) error {
	fileName := filepath.Base(inputFile)
	skipFiles := []string{"ni-lock.exe", "autorun.inf", "private.pem", "ni-lock.png", "public.pem"}
	if strings.HasSuffix(inputFile, ".ni-lock") || strings.HasSuffix(inputFile, ".ni-lock-aes") {
		return nil
	}

	for _, skipFile := range skipFiles {
		if fileName == skipFile {
			return nil
		}
	}
	return nil
}

func deProcessFilesInDirectory(directory string, processFunc func(string) error) error {
	var fileCount int
	var totalFileCount int

	var processErr error

	// 遍历目录并处理文件
	err := filepath.Walk(directory, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		if !info.IsDir() && info.Mode().IsRegular() { // 判断是否为普通文件
			fileName := filepath.Base(path)

			skipErr := deSkipFileCheck(path)
			if skipErr != nil {
				fmt.Println(skipErr)
				return nil
			}

			totalFileCount++
			fmt.Printf("\rProcessing file %d: %s", totalFileCount, fileName)
			processErr = processFunc(path)

			if processErr != nil {
				fmt.Printf("\nError processing file: %v", processErr)
				return processErr
			}

			fileCount++
			fmt.Printf("\rProgress: %.2f%%", float64(fileCount)/float64(totalFileCount)*100)
		}

		return nil
	})

	if processErr != nil {
		return processErr
	}

	return err
}

func deSkipFileCheck(inputFile string) error {
	fileName := filepath.Base(inputFile)
	skipFiles := []string{"ni-lock.exe", "autorun.inf", "private.pem", "ni-lock.png", "public.pem"}
	if !strings.HasSuffix(fileName, ".ni-lock") {
		return nil
	}

	for _, skipFile := range skipFiles {
		if fileName == skipFile {
			return fmt.Errorf("\rSkipping file %s", fileName)
		}
	}
	return nil
}

func isRunningOnRemovableDisk() bool {
	cmd := exec.Command("powershell", "Get-WmiObject Win32_LogicalDisk | Select-Object Caption, DriveType")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines[3:] {
		if strings.Contains(line, "2") {
			return true
		}
	}

	return false
}

func cleanAesKey(dirPath string) error {
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(path, ".ni-lock-aes") {
			if err := os.Remove(path); err != nil {
				return err
			}
		}
		return nil
	})

	if err != nil {
		return err
	}

	return nil
}

func getRemovableDisks() []string {
	cmd := exec.Command("powershell", "Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq 2 } | Select-Object -ExpandProperty DeviceID")
	output, err := cmd.Output()
	if err != nil {
		return []string{} // 如果出错，返回空切片
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\r\n")
	return lines
}

func decryptRemovableDisk(disk string, privateKeyFile string) error {
	fmt.Println("\n[ INFO ] Starting auto Decryption ...")

	var outputDir string
	err := deProcessFilesInDirectory(disk, func(file string) error {
		return decryptFile(file, privateKeyFile, outputDir)
	})
	if err != nil {
		errMsg := "\n[ ERRO ] Decryption failed!\n" + err.Error()
		fmt.Printf(red, errMsg)
	} else {
		err := cleanAesKey(disk)
		if err != nil {
			errMsg := "\n[ ERRO ] Failed to clean AES key file.\n" + err.Error()
			fmt.Printf(red, errMsg)
		}
		doneMsg1 := "\n[ INFO ] The AES key has been successfully cleared "
		fmt.Printf(green, doneMsg1)
		doneMsg := "\n[ INFO ] Decryption successful."
		fmt.Printf(green, doneMsg)
	}

	return nil
}

func checkDecryptionFlagExists(disk string) bool {
	flagFilePath := filepath.Join(disk, "decrypted.flag")
	_, err := os.Stat(flagFilePath)
	return err == nil
}

// 在U盘根目录添加标记文件
func addDecryptionFlag(disk string) error {
	flagFilePath := filepath.Join(disk, "decrypted.flag")
	flagFile, err := os.Create(flagFilePath)
	if err != nil {
		return err
	}
	defer flagFile.Close()

	fmt.Fprintf(flagFile, "This disk has been decrypted.")

	return nil
}
