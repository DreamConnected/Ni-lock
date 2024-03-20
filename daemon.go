package main

import (
	"fmt"
	"log"
	"time"

	"github.com/kardianos/service"
)

var isRunning bool = true

var logger service.Logger

var serviceConfig = &service.Config{
	Name:        "Ni-lock Daemon",
	DisplayName: "Ni-lock 守护进程",
	Description: "插入可移动磁盘时自动解密文件。",
}

type program struct{}

func (p *program) Start(s service.Service) error {
	// Start should not block. Do the actual work async.
	go p.run()
	return nil
}
func (p *program) run() {
	doneMsg := "\n[ INFO ] 这里是守护进程，获取有关命令帮助，请输入 ni-lock help 打印菜单！\n"
	fmt.Printf(green, doneMsg)
	// Do work here
	for isRunning {
		disks := getRemovableDisks()
		if len(disks) == 0 {
			time.Sleep(10 * time.Second)
			continue
		}

		for _, disk := range disks {
			if disk == "" {
				fmt.Println("[ INFO ] No removable disks found.")
				continue
			}
			// 检查是否已经解密过该磁盘
			if checkDecryptionFlagExists(disk) {
				fmt.Printf("\n[ INFO ] Disk %s has already been decrypted. Skipping...\n", disk)
				continue
			}

			fmt.Printf("\n[ INFO ] Found removable disk: %s\n", disk)

			err := decryptRemovableDisk(disk, privateKeyFile)
			if err != nil {
				doneMsg := "\n[ INFO ] 这里是守护进程，获取有关命令帮助，请输入 ni-lock help 打印菜单！\n"
				fmt.Printf(green, doneMsg)
				errMsg := "\n[ ERRO ] Decryption failed for disk " + disk + ": " + err.Error()
				fmt.Printf(red, errMsg)
			} else {
				doneMsg := "\n[ INFO ] 这里是守护进程，获取有关命令帮助，请输入 ni-lock help 打印菜单！\n"
				fmt.Printf(green, doneMsg)
				doneMsg2 := "\n[ INFO ] Decryption successful for disk " + disk
				fmt.Printf(green, doneMsg2)

				// 在U盘根目录添加标记文件
				err := addDecryptionFlag(disk)
				if err != nil {
					doneMsg := "\n[ INFO ] 这里是守护进程，获取有关命令帮助，请输入 ni-lock help 打印菜单！\n"
					fmt.Printf(green, doneMsg)
					errMsg := "\n[ ERRO ] Failed to add decryption flag for disk " + disk + ": " + err.Error()
					fmt.Printf(red, errMsg)
				}
			}
		}
		time.Sleep(5 * time.Second)
	}
}
func (p *program) Stop(s service.Service) error {
	// Stop should not block. Return with a few seconds.
	isRunning = false
	log.Println("Service stopped.")
	return nil
}
