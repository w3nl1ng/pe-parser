// 用来处理一些非 err != nil的错误，例如PE文件的格式不正确

package errorlog

import "log"

const (
	FILE_NOT_SET = "pe file not set"
)

func LogError(errType string) {
	log.Println(errType)
}
